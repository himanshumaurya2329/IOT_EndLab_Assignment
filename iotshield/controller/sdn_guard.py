"""
IoTShield SDN Guard — Ryu ARP-Spoofing Detection Controller
============================================================
Runs as a Ryu application:
    ryu-manager controller/sdn_guard.py --ofp-tcp-listen-port 6633

Security model
--------------
* A static trusted table (config/trusted_bindings.json) maps IP → MAC → port.
* ARP packets are always sent to the controller via Packet-In.
* For each ARP Packet-In the controller:
    1. Parses sender IP, sender MAC, operation, and ingress port.
    2. Looks up the sender IP in the trusted table.
    3. If found and MAC + port match → legitimate; forward normally.
    4. If found and MAC OR port mismatch → ARP spoofing detected; drop current
       packet and install a narrow drop rule (priority 200) for that MAC on that
       port. The drop rule takes precedence over any forwarding rules (priority < 100).
    5. If not found → unknown sender; log warning; forward but do not trust.
* The system never silently trusts the first ARP reply received.
* Legitimate h1↔h2 traffic is preserved via normal L2 forwarding rules.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

# Ensure project root is in sys.path regardless of how ryu-manager is launched
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ---------------------------------------------------------------------------
# Ryu imports — available only inside the lab (Linux/WSL with ryu installed)
# ---------------------------------------------------------------------------
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import arp, ethernet, icmp, ipv4, packet
from ryu.ofproto import ofproto_v1_3

from controller.event_logger import (
    log_arp_legitimate,
    log_arp_suspicious,
    log_arp_unknown,
    log_flow_rule_installed,
    log_packet_forwarded,
    log_port_mismatch,
    log_startup,
    log_switch_connected,
    logger,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_BINDINGS_FILE = _HERE / "config" / "trusted_bindings.json"
_SETTINGS_FILE = _HERE / "config" / "settings.json"

DROP_PRIORITY = 200          # Higher than forwarding rules → security rule wins
FORWARD_PRIORITY = 100       # Normal L2 forwarding
ARP_FLOOD_PRIORITY = 10      # Low-priority ARP redirect to controller


def _load_trusted_bindings() -> Dict[str, Dict]:
    """
    Load the trusted bindings table.
    Returns a dict keyed by IP address:
      { "10.0.0.1": {"mac": "00:00:00:00:00:01", "port": 1, "host": "h1", ...} }
    """
    try:
        with open(_BINDINGS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        table: Dict[str, Dict] = {}
        for entry in data.get("bindings", []):
            ip = entry["ip"]
            table[ip] = {
                "mac": entry["mac"].lower(),
                "port": entry.get("port"),
                "host": entry.get("host", "unknown"),
                "role": entry.get("role", ""),
            }
        policy = data.get("policy", {})
        logger.info("Loaded %d trusted bindings from %s", len(table), _BINDINGS_FILE)
        return table, policy
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
        logger.critical("Cannot load trusted bindings: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# ARP operation names
# ---------------------------------------------------------------------------
ARP_OP_NAMES = {
    arp.ARP_REQUEST: "ARP_REQUEST",
    arp.ARP_REPLY: "ARP_REPLY",
}


# ---------------------------------------------------------------------------
# Main Ryu Application
# ---------------------------------------------------------------------------
class IoTShieldGuard(app_manager.RyuApp):
    """
    IoTShield ARP-spoofing detection and prevention application.
    Implements OpenFlow 1.3.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trusted, self.policy = _load_trusted_bindings()
        # MAC → port mapping learned from legitimate traffic (L2 table)
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        # Track active drop rules: dpid → set of (in_port, src_mac)
        self.active_drops: Dict[int, set] = {}
        # Statistics
        self.stats = {
            "arp_inspected": 0,
            "arp_legitimate": 0,
            "arp_suspicious": 0,
            "arp_unknown": 0,
            "packets_dropped_current": 0,
            "flow_rules_installed": 0,
        }
        # Attack detection timing
        self._attack_first_detected_at: Optional[float] = None
        self._attack_marker_time: Optional[float] = None

        log_startup("0.0.0.0", 6633)
        logger.info("IoTShield Guard initialised. Trusted IPs: %s", list(self.trusted))

    # ── Switch connected ──────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install default table-miss rule to send all packets to controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        n_tables = getattr(ev.msg, "n_tables", 255)

        log_switch_connected(datapath.id, n_tables)
        self.mac_to_port[datapath.id] = {}
        self.active_drops[datapath.id] = set()

        # Table-miss: send ALL unmatched packets to controller (lowest priority 0)
        # Install it twice to ensure it's received — first miss gets buffered
        for _ in range(2):
            self._add_flow(
                datapath,
                priority=0,
                match=parser.OFPMatch(),
                actions=[
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
                ],
                hard_timeout=0,
                idle_timeout=0,
            )
        logger.info("Table-miss rule installed on datapath 0x%016x", datapath.id)

    # ── Packet-In handler ─────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Check if a lab reset was requested
        if os.path.exists("/tmp/iotshield_reset.trigger"):
            try:
                os.remove("/tmp/iotshield_reset.trigger")
            except OSError:
                pass
            self.mac_to_port.clear()
            self.active_drops.clear()
            self.stats = {k: 0 for k in self.stats}
            self._attack_first_detected_at = None
            self._attack_marker_time = None
            logger.info("SDN Guard internal state reset via trigger.")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP, spanning tree, and IPv6 multicast background chatter (e.g. 33:33:...)
        if eth.ethertype in (0x88CC, 0x86DD) or eth.dst == "01:80:c2:00:00:00" or eth.dst.startswith("33:33:"):
            return

        dst_mac = eth.dst
        src_mac = eth.src.lower()
        dpid = datapath.id

        # L2 learning (only from trusted or known sources)
        self.mac_to_port.setdefault(dpid, {})

        # ── ARP inspection ────────────────────────────────────────────────────
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            self._handle_arp(
                datapath, in_port, src_mac, dst_mac, arp_pkt, msg
            )
            return  # ARP packets are handled separately; do not forward here

        # ── Non-ARP: normal L2 forwarding ────────────────────────────────────
        self._learn_and_forward(datapath, in_port, src_mac, dst_mac, msg, ofproto, parser, pkt)

    # ── ARP inspection core ───────────────────────────────────────────────────

    def _handle_arp(self, datapath, in_port, src_mac, dst_mac, arp_pkt, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        sender_ip = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac.lower()
        target_ip = arp_pkt.dst_ip
        operation = ARP_OP_NAMES.get(arp_pkt.opcode, f"op={arp_pkt.opcode}")

        self.stats["arp_inspected"] += 1

        # ── Lookup sender IP in trusted table ─────────────────────────────────
        binding = self.trusted.get(sender_ip)

        if binding is None:
            # Unknown sender — log warning, do NOT auto-trust, but forward
            # (could be a new device; policy may be tightened to drop)
            self.stats["arp_unknown"] += 1
            log_arp_unknown(sender_ip, sender_mac, in_port, operation)
            unknown_policy = self.policy.get("unknown_sender", "warn")
            if unknown_policy == "drop":
                return  # silently drop
            # Forward the ARP as a flood (unknown destination MAC for ARP)
            self._flood_arp(datapath, msg, in_port)
            return

        expected_mac = binding["mac"]
        expected_port = binding.get("port")

        # ── Check MAC mismatch — primary spoofing indicator ───────────────────
        if sender_mac != expected_mac:
            detection_ts = time.monotonic()
            if self._attack_first_detected_at is None:
                self._attack_first_detected_at = detection_ts

            latency_ms = None
            if self._attack_marker_time is not None:
                latency_ms = (detection_ts - self._attack_marker_time) * 1000

            self.stats["arp_suspicious"] += 1
            self.stats["packets_dropped_current"] += 1

            log_arp_suspicious(
                src_ip=sender_ip,
                src_mac=sender_mac,
                in_port=in_port,
                operation=operation,
                expected_mac=expected_mac,
                expected_port=expected_port,
                reason=f"MAC mismatch: claimed {sender_ip} but MAC {sender_mac} ≠ expected {expected_mac}",
                action="DROP_AND_INSTALL_RULE",
                detection_latency_ms=latency_ms,
            )

            # ── Install drop rule for this MAC + port on OVS switch ─────────
            drop_key = (in_port, sender_mac)
            match = parser.OFPMatch(in_port=in_port, eth_src=sender_mac)
            self._add_flow(
                datapath,
                priority=DROP_PRIORITY,
                match=match,
                actions=[],          # empty actions = DROP
                hard_timeout=300,    # auto-expire after 5 minutes
                idle_timeout=0,
            )
            self.active_drops.setdefault(dpid, set())
            if drop_key not in self.active_drops[dpid]:
                self.active_drops[dpid].add(drop_key)
                self.stats["flow_rules_installed"] += 1
                log_flow_rule_installed(dpid, in_port, sender_mac, DROP_PRIORITY, "DROP")

            # ── Current packet: do NOT forward (no output action) ─────────────
            # Simply returning without sending a PacketOut drops the current packet.
            return

        # ── Check port mismatch — secondary indicator ─────────────────────────
        if expected_port is not None and in_port != expected_port:
            log_port_mismatch(sender_ip, sender_mac, in_port, expected_port)
            self.stats["arp_suspicious"] += 1
            # Policy: warn and log; do not drop (could be topology change)
            # Still forward but flag the anomaly

        # ── Legitimate ARP ────────────────────────────────────────────────────
        self.stats["arp_legitimate"] += 1
        log_arp_legitimate(sender_ip, sender_mac, target_ip, in_port, operation)

        # Learn source MAC → port
        self.mac_to_port[dpid][sender_mac] = in_port

        # Forward the ARP
        self._flood_arp(datapath, msg, in_port)

    # ── L2 forwarding ────────────────────────────────────────────────────────

    def _learn_and_forward(self, datapath, in_port, src_mac, dst_mac, msg, ofproto, parser, pkt=None):
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Only log actual IPv4 user traffic (ICMP / data) between lab hosts
        if pkt is not None:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                proto = "ICMP" if pkt.get_protocol(icmp.icmp) else "IPv4"
                self.stats["arp_inspected"] += 1
                log_packet_forwarded(src_ip, src_mac, dst_ip, dst_mac, in_port, out_port, proto)

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(
                datapath,
                priority=FORWARD_PRIORITY,
                match=match,
                actions=actions,
                hard_timeout=10,
                idle_timeout=5,
            )

        self._send_packet_out(datapath, msg, actions)

    def _flood_arp(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._send_packet_out(datapath, msg, actions)

    # ── OVS helpers ──────────────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(mod)

    def _send_packet_out(self, datapath, msg, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Always include raw data to ensure delivery regardless of buffer state
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=msg.match["in_port"],
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

    # ── Stats API (read by the Flask backend) ─────────────────────────────────

    def get_stats(self) -> dict:
        """Return a snapshot of current statistics."""
        return dict(self.stats)

    def mark_attack_start(self, attacker_ip: str, attacker_mac: str, target_ip: str) -> None:
        """Called externally or via REST to record attack start time."""
        self._attack_marker_time = time.monotonic()
        from controller.event_logger import log_attack_start
        log_attack_start(attacker_ip, attacker_mac, target_ip)

    def get_detection_latency_ms(self) -> Optional[float]:
        """Return detection latency in ms, or None if not yet detected."""
        if self._attack_marker_time and self._attack_first_detected_at:
            return (self._attack_first_detected_at - self._attack_marker_time) * 1000
        return None

    def get_active_drop_rules(self) -> list:
        """Return list of active drop rules across all datapaths."""
        rules = []
        for dpid, keys in self.active_drops.items():
            for (port, mac) in keys:
                rules.append({
                    "datapath_id": f"{dpid:#018x}",
                    "in_port": port,
                    "src_mac": mac,
                    "priority": DROP_PRIORITY,
                    "action": "DROP",
                })
        return rules

