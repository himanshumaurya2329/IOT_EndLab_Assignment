# IoTShield Viva Questions and Answers

*See README.md Section 26 for the full 20 Q&A set.*

This file provides additional quick-reference answers for common viva questions.

---

## Quick Reference Answers

**Q: What does the Ryu controller do when it receives an ARP Packet-In?**

A: It parses the sender IP and MAC from the ARP payload, looks up the sender IP in the trusted binding table, and compares the received MAC with the expected MAC. If they match, the packet is forwarded (legitimate). If they don't match, the current packet is dropped (no PacketOut is sent) and a Flow-Mod is sent to install a DROP rule at priority 200.

**Q: What OpenFlow messages does IoTShield use?**

A: Three main messages:
1. `OFPFlowMod` — installs flow rules (table-miss, forwarding, drop)
2. `OFPPacketOut` — sends a packet from the controller back to the switch for forwarding
3. `OFPPacketIn` — received by the controller from the switch (incoming packet event)

**Q: How is the trusted binding table structured?**

A:
```json
{
  "bindings": [
    {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1, "host": "h1"},
    {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2, "host": "h2"},
    {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3, "host": "h3"}
  ],
  "policy": {"unknown_sender": "warn", "auto_trust_unknown": false}
}
```

**Q: What is the role of `hard_timeout=300` in the drop rule?**

A: It makes the drop rule automatically expire after 300 seconds (5 minutes). This prevents permanent quarantine of an attacker who has stopped attacking, allowing the administrator to reset the lab cleanly. In production, the timeout would be longer or managed manually.

**Q: What happens if two Ryu Packet-In events for the same attacker arrive simultaneously?**

A: The check `if drop_key not in self.active_drops.get(dpid, set())` ensures the Flow-Mod is only sent once. Python's GIL prevents true concurrency in the Ryu event loop. The second event would either be handled after the first (and the drop_key already present) or be processed by the same drop rule if OVS installed it fast enough.

**Q: Why does the first spoofed packet get dropped even though the OVS drop rule isn't installed yet?**

A: When the controller handles a Packet-In, the default behavior is that the packet is NOT forwarded unless the controller explicitly sends a PacketOut message. In `_handle_arp()`, when a spoofing event is detected, the function simply returns without calling `_send_packet_out()`. This means no PacketOut is sent → OVS does not forward the packet → it is silently dropped.

**Q: How does the event log reach the Flask backend?**

A: The Ryu controller writes events to `/tmp/iotshield_events.jsonl` (one JSON object per line). The `EventService` class in the Flask backend runs a background thread (`_tail_loop`) that checks the file every 250ms for new content. When new lines are found, they are parsed as JSON and pushed to all SSE subscriber queues.

**Q: What prevents the dashboard from fabricating attack data?**

A: In live mode, the dashboard only displays events that come from the SSE stream, which in turn only emits events that were written to the JSONL file by the Ryu controller. The demo mode events are all clearly tagged with `"demo": true` and are displayed with a yellow DEMO banner. The backend API includes `"demo_mode": true/false` in every response.

