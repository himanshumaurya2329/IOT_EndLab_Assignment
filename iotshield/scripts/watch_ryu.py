#!/usr/bin/env python3
"""
IoTShield — Ryu Controller Log Formatter (Terminal 2)
======================================================
Formats /tmp/iotshield_ryu.log in a clean, readable way
by filtering out Ryu's noisy deprecation warnings.

Usage:  python3 scripts/watch_ryu.py
"""

import os, sys, time, re

BOLD="\033[1m"; RESET="\033[0m"; DIM="\033[2m"
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; WHITE="\033[97m"

RYU_LOG = "/tmp/iotshield_ryu.log"

# Lines containing these strings are suppressed (Ryu internal noise)
SUPPRESS = [
    "EventletDeprecationWarning",
    "import eventlet",
    "deprecated",
    "migration.html",
    "asyncio",
    "framework",
    "strongly recommend",
    "bugfix mode",
    "If you are",
    "we recommend",
    "RLock(s) were not",
    "make sure you run",
    "loading app ryu.controller",
    "instantiating app ryu.controller",
]

def should_suppress(line):
    low = line.lower()
    return any(s.lower() in low for s in SUPPRESS)

def format_line(line):
    line = line.strip()
    if not line:
        return None
    if should_suppress(line):
        return None

    # Color code by content
    if "SPOOFING" in line or "CRITICAL" in line or "DROP" in line.upper():
        return f"{RED}{BOLD}  🚨 {line}{RESET}"
    if "Table-miss rule installed" in line or "Controller connected" in line:
        return f"{GREEN}  ✔  {line}{RESET}"
    if "Switch 0x" in line and "connected" in line:
        return f"{CYAN}  🔌 {line}{RESET}"
    if "loading app controller" in line or "instantiating app controller" in line:
        return f"{CYAN}  ⚙  {line}{RESET}"
    if "Loaded" in line and "bindings" in line:
        return f"{GREEN}  🔐 {line}{RESET}"
    if "listening on" in line:
        return f"{GREEN}  ✔  {line}{RESET}"
    if "Legitimate" in line:
        return f"{GREEN}  🟢 {line}{RESET}"
    if "Drop rule installed" in line or "FLOW_RULE" in line:
        return f"{YELLOW}  ⚡ {line}{RESET}"
    if "ERROR" in line or "FAIL" in line:
        return f"{RED}  ✘  {line}{RESET}"
    if "WARNING" in line or "WARN" in line:
        return f"{YELLOW}  ⚠  {line}{RESET}"
    if "INFO" in line:
        return f"  {DIM}{line}{RESET}"
    return f"  {line}"

def main():
    print(f"\n{CYAN}{BOLD}╔═══════════════════════════════════════════════════════════════════╗")
    print(f"║         ⚙  IoTShield Ryu SDN Controller Log — Terminal 2          ║")
    print(f"║          (Filtered: Ryu deprecation warnings suppressed)            ║")
    print(f"╚═══════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {DIM}Watching: {RYU_LOG}   |  Ctrl+C to stop{RESET}\n")

    while not os.path.exists(RYU_LOG):
        print(f"  {DIM}Waiting for Ryu to start...{RESET}", end="\r")
        time.sleep(0.5)
    print(f"  {GREEN}✓ Ryu controller log connected.{RESET}\n")

    file_pos = 0
    # Read existing log
    try:
        with open(RYU_LOG,"r",encoding="utf-8",errors="replace") as f:
            for line in f:
                out = format_line(line)
                if out: print(out)
            file_pos = f.tell()
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")

    # Tail new lines
    while True:
        try:
            if not os.path.exists(RYU_LOG):
                time.sleep(0.5); continue
            size = os.path.getsize(RYU_LOG)
            if size < file_pos:
                print(f"\n{CYAN}─── Log cleared / Ryu restarted ───{RESET}\n")
                file_pos = 0
            if size > file_pos:
                with open(RYU_LOG,"r",encoding="utf-8",errors="replace") as f:
                    f.seek(file_pos)
                    for line in f.readlines():
                        out = format_line(line)
                        if out: print(out)
                    file_pos = f.tell()
            time.sleep(0.3)
        except KeyboardInterrupt:
            print(f"\n{DIM}Monitor stopped.{RESET}\n")
            break
        except Exception:
            time.sleep(0.5)

if __name__ == "__main__":
    main()

