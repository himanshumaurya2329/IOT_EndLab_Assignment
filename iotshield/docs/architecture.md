# IoTShield Architecture

## Component Overview

IoTShield consists of four loosely-coupled layers communicating through files, ports, and HTTP:

```
┌─────────────────────────────────────────────────────┐
│  Data Plane (Mininet + OVS)                         │
│  h1 ─── s1 ─── h2                                  │
│          │                                           │
│         h3                                          │
└──────────────┬──────────────────────────────────────┘
               │ OpenFlow 1.3 (TCP :6633)
┌──────────────▼──────────────────────────────────────┐
│  Control Plane (Ryu)                                │
│  sdn_guard.py  ←→  event_logger.py                 │
│                          │                           │
│                    JSONL event log                   │
└──────────────────────────┬──────────────────────────┘
                           │ file tail (250ms poll)
┌──────────────────────────▼──────────────────────────┐
│  API Layer (Flask)                                   │
│  app.py  ←→  event_service.py  ←→  metrics.py      │
└──────────────────────────┬──────────────────────────┘
                           │ HTTP / SSE
┌──────────────────────────▼──────────────────────────┐
│  Presentation Layer (Browser)                       │
│  index.html  app.js  dashboard.js  topology.js      │
└─────────────────────────────────────────────────────┘
```

## Mininet Topology

```mermaid
graph LR
    H1["h1\n10.0.0.1/24\n00:00:00:00:00:01\nIoT Sensor / Victim"]
    H2["h2\n10.0.0.2/24\n00:00:00:00:00:02\nTrusted Server"]
    H3["h3\n10.0.0.3/24\n00:00:00:00:00:03\nAttacker"]
    S1["s1\nOpen vSwitch\nOpenFlow 1.3"]
    C0["Ryu Controller\n127.0.0.1:6633"]

    H1 -- "port 1" --- S1
    H2 -- "port 2" --- S1
    H3 -- "port 3" --- S1
    S1 -- "OpenFlow 1.3" --- C0
```

## ARP Processing Pipeline

```mermaid
flowchart TD
    PKT["Packet arrives at OVS"] --> MATCH["Match flow table"]
    MATCH -->|"Matched rule"| FWD["Execute rule actions (forward/drop)"]
    MATCH -->|"Table-miss (priority=0)"| PKTIN["Packet-In to Ryu"]

    PKTIN --> PARSE["Parse: eth_type, src_mac, in_port"]
    PARSE --> ISARP{Is ARP?}

    ISARP -->|No| L2["L2 Learning + Forward"]
    ISARP -->|Yes| LOOKUP["Lookup sender_ip in trusted_bindings"]

    LOOKUP --> FOUND{Found?}
    FOUND -->|No| UNKNOWN["Unknown sender\nPolicy: warn + forward"]
    FOUND -->|Yes| MACCHECK{MAC matches?}

    MACCHECK -->|Yes| PORTCHECK{Port matches?}
    PORTCHECK -->|Yes| LEGIT["Legitimate ARP\nLog + Forward"]
    PORTCHECK -->|No| PORTMM["Port Mismatch\nLog warning + Forward"]

    MACCHECK -->|No| SPOOF["⚠ ARP SPOOFING DETECTED"]
    SPOOF --> DROP1["Drop current packet\n(no PacketOut)"]
    SPOOF --> RULE["Install Flow-Mod\npriority=200, hard_timeout=300\nmatch: in_port=X, eth_src=MAC\nactions: drop"]
    SPOOF --> LOG["Log ARP_SPOOFING_DETECTED\nto JSONL event file"]
```

## OpenFlow Flow Rule Table

| Priority | Match | Actions | Purpose |
|---|---|---|---|
| 200 | `in_port=3, eth_src=00:00:00:00:00:03` | `drop` | Block attacker MAC (installed on detection) |
| 100 | `in_port=1, eth_dst=00:00:00:00:00:02` | `output:2` | Forward h1→h2 traffic |
| 100 | `in_port=2, eth_dst=00:00:00:00:00:01` | `output:1` | Forward h2→h1 traffic |
| 0 | `*` (table-miss) | `CONTROLLER:65535` | Send unmatched packets to Ryu |

**Priority precedence:** Security (200) > Forwarding (100) > Table-miss (0)

## Attack-Detection Mitigation Sequence

```mermaid
sequenceDiagram
    participant ATK as arp_spoof.py (h3)
    participant OVS as s1 (Open vSwitch)
    participant RYU as sdn_guard.py (Ryu)
    participant LOG as event_logger.py
    participant EVT as event_service.py
    participant UI  as Browser Dashboard

    ATK->>OVS: Spoofed ARP Reply<br/>psrc=10.0.0.2, hwsrc=00:00:00:00:00:03
    OVS->>RYU: Packet-In (table-miss, priority=0)
    RYU->>RYU: classify_arp()<br/>IP=10.0.0.2 → expected MAC=00:00:00:00:00:02<br/>got MAC=00:00:00:00:00:03 → MISMATCH
    RYU->>LOG: log_arp_suspicious(...)
    LOG->>LOG: Write JSONL line to /tmp/iotshield_events.jsonl
    RYU->>OVS: Flow-Mod (DROP, priority=200, hard_timeout=300)
    Note over RYU: Return without sending PacketOut<br/>→ current packet is dropped
    EVT->>LOG: Tail file (every 250ms)
    EVT->>EVT: Parse new JSONL line
    EVT->>UI: SSE: data: {"type":"ARP_SPOOFING_DETECTED",...}
    UI->>UI: Update counters, event table, topology animation

    ATK->>OVS: Next spoofed ARP Reply (same MAC)
    OVS->>OVS: Match DROP rule (priority=200)
    Note over OVS: Dropped by OVS kernel datapath<br/>Never reaches Ryu controller
```

## Data Flow: Events to Browser

```mermaid
flowchart LR
    RYU["sdn_guard.py\nRyu App"] -->|"calls"| EL["event_logger.py\n_write_event()"]
    EL -->|"append JSON line"| JSONL["/tmp/iotshield_events.jsonl"]
    JSONL -->|"tail every 250ms"| ES["event_service.py\nEventService._tail_loop()"]
    ES -->|"parse + ingest"| BUF["deque buffer\n(maxlen=500)"]
    BUF -->|"notify"| Q["SimpleQueue\nper SSE subscriber"]
    Q -->|"stream"| SSE["Flask SSE\nGET /api/events/stream"]
    SSE -->|"data: {...}\\n\\n"| ESRC["Browser EventSource\napp.js"]
    ESRC -->|"dispatch"| DASH["DashboardModule\n.onEvent()"]
    ESRC -->|"dispatch"| TOPO["TopologyModule\n.onEvent()"]
    ESRC -->|"dispatch"| CHT["ChartsModule\n.onEvent()"]
```

