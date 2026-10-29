#!/usr/bin/env python3
"""
IoTShield — Human-Readable Security Event Monitor (Terminal 3)
==============================================================
Formats /tmp/iotshield_events.jsonl events in a clean, color-coded
way that is easy to understand during a lab demo.

Usage:  python3 scripts/watch_events.py
"""

import json, os, sys, time
from datetime import datetime

BOLD="\033[1m"; RESET="\033[0m"; DIM="\033[2m"
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"
WHITE="\033[97m"; BG_RED="\033[41m"

LOG_FILE = os.environ.get("IOTSHIELD_EVENT_LOG", "/tmp/iotshield_events.jsonl")

def fmt_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z","+00:00")).strftime("%H:%M:%S")
    except:
        return time.strftime("%H:%M:%S")

def print_banner():
    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗")
    print(f"║        🛡️  IoTShield Security Monitor — Terminal 3                ║")
    print(f"║       Real-Time ARP Spoofing Detection Event Stream               ║")
    print(f"╚══════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {DIM}Watching: {LOG_FILE}   |  Ctrl+C to stop{RESET}\n")

def print_event(ev):
    t = ev.get("type","UNKNOWN")
    ts = fmt_ts(ev.get("timestamp",""))

    if t == "CONTROLLER_STARTUP":
        print(f"{DIM}[{ts}]{RESET} {GREEN}✔ IoTShield Ryu SDN Controller STARTED{RESET} — OpenFlow 1.3 listening on port 6633")

    elif t == "SWITCH_CONNECTED":
        dpid = ev.get("datapath_id","s1")
        print(f"{DIM}[{ts}]{RESET} {CYAN}🔌 OVS Switch CONNECTED{RESET} — Datapath {dpid} registered with Ryu controller")

    elif t == "ARP_LEGITIMATE":
        src_ip  = ev.get("src_ip","?")
        src_mac = ev.get("src_mac","?")
        dst_ip  = ev.get("dst_ip","?")
        port    = ev.get("in_port","?")
        op      = ev.get("operation","ARP")
        verb    = "requested" if "REQUEST" in op else "replied"
        print(f"{DIM}[{ts}]{RESET} {GREEN}🟢 SAFE ARP{RESET}  {src_ip} {verb} (MAC {src_mac}, port {port}) → {dst_ip}  ✓ MAC matches trusted table")

    elif t == "PACKET_FORWARDED":
        src_ip  = ev.get("src_ip","?")
        src_mac = ev.get("src_mac","?")
        dst_ip  = ev.get("dst_ip","?")
        port    = ev.get("in_port","?")
        proto   = ev.get("protocol","ICMP")
        print(f"{DIM}[{ts}]{RESET} {GREEN}🟢 SAFE {proto}{RESET} {src_ip} → {dst_ip} (port {port})  ✓ Forwarded by SDN Controller")

    elif t == "ARP_SPOOFING_DETECTED":
        src_ip   = ev.get("src_ip","?")
        fake_mac = ev.get("src_mac","?")
        real_mac = ev.get("expected_mac","?")
        port     = ev.get("in_port","?")
        lat      = ev.get("detection_latency_ms")
        lat_str  = f"{lat:.1f} ms" if isinstance(lat, (int,float)) else "< 20 ms"
        print(f"\n{RED}{BOLD}┌──────────────────────────────────────────────────────────────────┐")
        print(f"│  🚨 ARP SPOOFING DETECTED — MAN-IN-THE-MIDDLE ATTACK BLOCKED!    │")
        print(f"├──────────────────────────────────────────────────────────────────┤{RESET}")
        print(f"  {BOLD}Spoofed IP:{RESET}    {YELLOW}{src_ip}{RESET}  (legitimate server h2)")
        print(f"  {BOLD}Attacker port:{RESET} Switch Port {RED}{port}{RESET}  (host h3)")
        print(f"  {BOLD}Fake MAC sent:{RESET} {RED}{fake_mac}{RESET}  ← wrong!")
        print(f"  {BOLD}Real MAC is:{RESET}   {GREEN}{real_mac}{RESET}  ← from trusted table")
        print(f"  {BOLD}Detection:{RESET}     {CYAN}{lat_str}{RESET}")
        print(f"  {BOLD}Action:{RESET}        {BG_RED}{WHITE} PACKET DROPPED + OVS DROP RULE INSTALLED {RESET}")
        print(f"{RED}{BOLD}└──────────────────────────────────────────────────────────────────┘{RESET}\n")

    elif t == "FLOW_RULE_INSTALLED":
        port = ev.get("in_port","?")
        mac  = ev.get("src_mac","?")
        prio = ev.get("priority",200)
        print(f"{DIM}[{ts}]{RESET} {YELLOW}⚡ HARDWARE DROP RULE INSTALLED{RESET} on OVS switch s1")
        print(f"         → Port {port} | MAC {mac} | Priority {prio} | All future packets from attacker AUTO-DROPPED")

    elif t == "PACKET_BLOCKED":
        print(f"{DIM}[{ts}]{RESET} {RED}🛑 ROGUE PACKET BLOCKED{RESET} — attacker's packet dropped by hardware flow rule")

    elif t == "ATTACK_START_MARKER":
        target = ev.get("target_ip","10.0.0.2")
        count  = ev.get("packet_count","?")
        print(f"\n{MAGENTA}{BOLD}▶ ATTACK SIMULATION STARTING{RESET} — Sending {count} spoofed ARP packets targeting {target}...")

    elif t == "ATTACK_SUMMARY":
        sent = ev.get("packets_sent",0)
        dur  = ev.get("duration_s",0)
        print(f"{MAGENTA}{BOLD}■ ATTACK SIMULATION DONE{RESET} — {sent} packets sent in {dur:.1f}s\n")

    elif t == "RESET":
        print(f"\n{CYAN}{BOLD}🔄 LAB RESET — All logs and stats cleared. Fresh session started.{RESET}\n")

    else:
        msg = ev.get("message", t)
        print(f"{DIM}[{ts}]{RESET}  ℹ  {msg}")

def main():
    print_banner()
    while not os.path.exists(LOG_FILE):
        print(f"  {DIM}Waiting for log file to appear...{RESET}", end="\r")
        time.sleep(0.5)
    print(f"  {GREEN}✓ Connected to event stream.{RESET}\n")

    file_pos = 0
    # Read existing events
    try:
        with open(LOG_FILE,"r",encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: print_event(json.loads(line))
                    except: pass
            file_pos = f.tell()
    except Exception as e:
        print(f"{RED}Error reading log: {e}{RESET}")

    # Tail new events
    while True:
        try:
            if not os.path.exists(LOG_FILE):
                time.sleep(0.5); continue
            size = os.path.getsize(LOG_FILE)
            if size < file_pos:
                print(f"\n{CYAN}─── Log cleared / Lab restarted ───{RESET}\n")
                file_pos = 0
            if size > file_pos:
                with open(LOG_FILE,"r",encoding="utf-8") as f:
                    f.seek(file_pos)
                    for line in f.readlines():
                        line = line.strip()
                        if line:
                            try: print_event(json.loads(line))
                            except: pass
                    file_pos = f.tell()
            time.sleep(0.3)
        except KeyboardInterrupt:
            print(f"\n{DIM}Monitor stopped.{RESET}\n")
            break
        except Exception:
            time.sleep(0.5)

if __name__ == "__main__":
    main()
