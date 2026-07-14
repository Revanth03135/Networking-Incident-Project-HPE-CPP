# Network Incident Investigation Report

---

## 1. Executive Summary

| Field | Value |
|---|---|
| **Investigation Date** | 2026-07-14 |
| **Device(s) Analyzed** | Campus-Core-01, Floor3-Access-01, WAN-Router-01 |
| **Logs Analyzed** | 47 |
| **Reconstructed Incidents** | **4** — proven causal chain + RCA |
| **Standalone Alerts** | 0 |
| **Operational Workflows** | 3 |
| **Routine Informational Events** | 11 |
| **Highest Severity Observed** | Critical |
| **Overall Investigation Status** | Active — Unresolved incidents require immediate attention |

> **4 incident(s)** have a proven causal chain and receive full Root Cause Analysis below.
> The remaining 14 events are categorized as alerts (0), workflows (3), or routine (11) — none of these are incidents.

---

## 2. Investigation Scope

This investigation covers 47 log events collected from 3 device(s) (Campus-Core-01, Floor3-Access-01, WAN-Router-01) between 2026-07-14 09:00:01 UTC and 2026-07-14 09:09:30 UTC. A total of 4 incident(s) were reconstructed with full RCA, alongside 0 standalone alert(s), 3 operational workflow(s), and 11 routine informational event(s) — overall status: Active.

---

## 3. Incident Classification Summary

| Category | Count | IDs / Labels |
|---|---|---|
| Logs Analyzed | 47 | All parsed log events |
| **Reconstructed Incidents (RCA)** | **4** | INC-0003, INC-0005, INC-0006, INC-0009 |
| Standalone Alerts | 0 | None |
| Operational Workflows | 3 | WORKFLOW-0002, WORKFLOW-0008, WORKFLOW-0013 |
| Routine Informational Events | 11 | Ntp, Snmp, Dot1X Success, Interface Up, Lldp Neighbor Discovered, Vlan |

> **How to read this table:** Only Reconstructed Incidents have a proven causal chain.
> Standalone alerts, workflows, and routine events are **not incidents** — classified separately below.

---

## 4. Reconstructed Incidents — Full Root Cause Analysis

> Only **4** incident(s) below have a proven causal chain.
> Each section: Incident Overview (incl. impact) · Timeline · Root Cause · Cause-Effect Chain · Supporting Evidence · Recommendations

---

### Incident INC-0003 — Crc Errors -> Interface Down

#### 4.1.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0003 |
| **Status** | Resolved |
| **Start Time** | 2026-07-14 09:01:00 UTC |
| **End Time** | 2026-07-14 09:04:10 UTC |
| **Duration** | 190.0s |
| **Severity** | Warning |
| **Affected Device** | Campus-Core-01 |
| **Affected Interface(s)** | 1/1/25 |
| **Events in Chain** | 16 |
| **Causal Confidence** | 75% |
| **Confidence Reasons** | ✓ Same interface<br>✓ Recovery observed<br>✓ Temporal proximity<br>✓ Known propagation chain |

#### 4.1.2  Timeline Reconstruction

```
2026-07-14 09:01:00 UTC
[WARNING]  Crc Errors
       Excessive CRC errors detected on interface 1/1/25
        |
        v

2026-07-14 09:01:04 UTC
[INFO]  Interface Down
       Link down on interface 1/1/25
        |
        v

2026-07-14 09:01:05 UTC
[INFO]  Interface Down
       Interface 1/1/25 operational status changed to DOWN
        |
        v

2026-07-14 09:01:06 UTC
[WARNING]  Ospf Neighbor Down
       OSPF neighbor 10.1.1.2 on interface 1/1/25 changed state from FULL to DOWN
        |
        v

2026-07-14 09:01:07 UTC
[INFO]  Route Recalculation Started
       Routing table recalculation started
        |
        v

2026-07-14 09:01:08 UTC
[INFO]  Route Recalculation Completed
       Routing table recalculation completed
        |
        v

2026-07-14 09:01:10 UTC
[WARNING]  Bgp Session Lost
       BGP peer 10.1.1.2 session lost
        |
        v

2026-07-14 09:01:12 UTC
[INFO]  Lldp Neighbor Removed
       LLDP neighbor removed from port 1/1/25
        |
        v

2026-07-14 09:01:15 UTC
[WARNING]  Stp Topology Change
       Instance 0: Topology change detected on port 1/1/25, recalculating spanning tree
```

#### 4.1.3  Recovery Events

**Status = RESOLVED** (Recovery Duration: 190 seconds)

- Interface Up
- Interface Up
- Ospf Neighbor Up
- Bgp Session Established
- Routes Relearned
- Stp Converged
- Lldp Neighbor Discovered

#### 4.1.4  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Crc Errors |
| **Root Trigger Event** | Excessive CRC errors detected on interface 1/1/25 |
| **Device** | Campus-Core-01 |
| **Causal Confidence** | 75% |
| **Causal Links Found** | 19 |

#### 4.1.5  Propagation

**Root Cause:** Crc Errors on Campus-Core-01

**Propagation:**
Crc Errors -> Interface Down -> Interface Down -> Ospf Neighbor Down -> Lldp Neighbor Removed -> Stp Topology Change -> Recovery Completed

#### 4.1.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 09:01:00 | 4 | 1/1/25 | Warning | Crc Errors | Excessive CRC errors detected on interface 1/1/25 |
| 2026-07-14 09:01:04 | 6 | 1/1/25 | Info | Interface Down | Link down on interface 1/1/25 |
| 2026-07-14 09:01:05 | 7 | 1/1/25 | Info | Interface Down | Interface 1/1/25 operational status changed to DOWN |
| 2026-07-14 09:01:06 | 8 | 1/1/25 | Warning | Ospf Neighbor Down | OSPF neighbor 10.1.1.2 on interface 1/1/25 changed state from FULL to DOWN |
| 2026-07-14 09:01:07 | 9 | — | Info | Route Recalculation Started | Routing table recalculation started |
| 2026-07-14 09:01:08 | 10 | — | Info | Route Recalculation Completed | Routing table recalculation completed |
| 2026-07-14 09:01:10 | 11 | — | Warning | Bgp Session Lost | BGP peer 10.1.1.2 session lost |
| 2026-07-14 09:01:12 | 12 | 1/1/25 | Info | Lldp Neighbor Removed | LLDP neighbor removed from port 1/1/25 |
| 2026-07-14 09:01:15 | 13 | 1/1/25 | Warning | Stp Topology Change | Instance 0: Topology change detected on port 1/1/25, recalculating spanning tree |
| 2026-07-14 09:04:00 | 24 | 1/1/25 | Info | Interface Up | Port 1/1/25 is now on-line |
| 2026-07-14 09:04:01 | 25 | 1/1/25 | Info | Interface Up | Interface 1/1/25 operational status changed to UP |
| 2026-07-14 09:04:02 | 26 | 1/1/25 | Info | Ospf Neighbor Up | OSPF neighbor 10.1.1.2 on interface 1/1/25 changed state from DOWN to FULL |
| 2026-07-14 09:04:03 | 27 | — | Info | Bgp Session Established | BGP peer 10.1.1.2 session established |
| 2026-07-14 09:04:04 | 28 | — | Info | Routes Relearned | Routes successfully relearned |
| 2026-07-14 09:04:05 | 29 | — | Info | Stp Converged | Instance 0: Topology converged, root bridge unchanged |
| 2026-07-14 09:04:10 | 30 | 1/1/25 | Info | Lldp Neighbor Discovered | LLDP neighbor discovered on port 1/1/25 |

#### 4.1.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Replace cable or transceiver** | CRC errors indicate signal integrity problems |
| 2 | **Check port error counters** | Persistent CRC errors may require port replacement |

---

### Incident INC-0005 — Dot1X Failure -> Radius Failure

#### 4.2.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0005 |
| **Status** | Active |
| **Start Time** | 2026-07-14 09:03:00 UTC |
| **End Time** | 2026-07-14 09:03:20 UTC |
| **Duration** | 20.0s |
| **Severity** | Error |
| **Affected Device** | Floor3-Access-01 |
| **Affected Interface(s)** | 1/1/10, 1/1/11 |
| **Events in Chain** | 6 |
| **Causal Confidence** | 0% |
| **Confidence Reasons** | ✓ Temporal proximity<br>✓ Known propagation chain |

#### 4.2.2  Timeline Reconstruction

```
2026-07-14 09:03:00 UTC
[ERROR]  Dot1X Failure
       802.1x: Authentication failed for client AA:BB:CC:DD:EE:01 on port 1/1/10
        |
        v

2026-07-14 09:03:06 UTC
[ERROR]  Dot1X Failure
       802.1x: Authentication failed for client AA:BB:CC:DD:EE:02 on port 1/1/11
        |
        v

2026-07-14 09:03:12 UTC
[ERROR]  Radius Failure
       RADIUS server 192.168.10.5 unreachable, authentication timeout
        |
        v

2026-07-14 09:03:15 UTC
[ERROR]  Radius Failure
       RADIUS server 192.168.10.6 unreachable, authentication timeout
        |
        v

2026-07-14 09:03:18 UTC
[WARNING]  Port Blocked
       Port 1/1/10 blocked due to repeated authentication failures
        |
        v

2026-07-14 09:03:20 UTC
[WARNING]  Port Blocked
       Port 1/1/11 blocked due to repeated authentication failures
```

#### 4.2.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Radius Failure |
| **Root Trigger Event** | RADIUS server 192.168.10.5 unreachable, authentication timeout |
| **Device** | Floor3-Access-01 |
| **Causal Confidence** | 0% |
| **Causal Links Found** | 12 |

#### 4.2.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 09:03:00 | 16 | 1/1/10 | Error | Dot1X Failure | 802.1x: Authentication failed for client AA:BB:CC:DD:EE:01 on port 1/1/10 |
| 2026-07-14 09:03:06 | 18 | 1/1/11 | Error | Dot1X Failure | 802.1x: Authentication failed for client AA:BB:CC:DD:EE:02 on port 1/1/11 |
| 2026-07-14 09:03:12 | 20 | — | Error | Radius Failure | RADIUS server 192.168.10.5 unreachable, authentication timeout |
| 2026-07-14 09:03:15 | 21 | — | Error | Radius Failure | RADIUS server 192.168.10.6 unreachable, authentication timeout |
| 2026-07-14 09:03:18 | 22 | 1/1/10 | Warning | Port Blocked | Port 1/1/10 blocked due to repeated authentication failures |
| 2026-07-14 09:03:20 | 23 | 1/1/11 | Warning | Port Blocked | Port 1/1/11 blocked due to repeated authentication failures |

#### 4.2.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Investigate root cause device and interface** | device=Floor3-Access-01, interface=1/1/10, 1/1/11 |
| 2 | **Add monitoring alerts for this event type** | subtype=radius_failure |

---

### Incident INC-0006 — Bgp Session Lost -> Route Withdrawal -> Ospf Neighbor Down

#### 4.3.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0006 |
| **Status** | Resolved |
| **Start Time** | 2026-07-14 09:05:00 UTC |
| **End Time** | 2026-07-14 09:08:05 UTC |
| **Duration** | 185.0s |
| **Severity** | Warning |
| **Affected Device** | WAN-Router-01 |
| **Affected Interface(s)** | — |
| **Events in Chain** | 8 |
| **Causal Confidence** | 60% |
| **Confidence Reasons** | ✓ Recovery observed<br>✓ Temporal proximity<br>✓ Known propagation chain |

#### 4.3.2  Timeline Reconstruction

```
2026-07-14 09:05:00 UTC
[WARNING]  Bgp Session Lost
       BGP peer 203.0.113.1 session lost
        |
        v

2026-07-14 09:05:02 UTC
[INFO]  Route Withdrawal
       Route withdrawal initiated for prefix 0.0.0.0/0
        |
        v

2026-07-14 09:05:05 UTC
[WARNING]  Ospf Neighbor Down
       OSPF neighbor 10.99.0.1 changed state from FULL to DOWN
        |
        v

2026-07-14 09:05:08 UTC
[INFO]  Route Recalculation Started
       Routing table recalculation started
        |
        v

2026-07-14 09:05:10 UTC
[INFO]  Route Recalculation Completed
       Routing table recalculation completed
```

#### 4.3.3  Recovery Events

**Status = RESOLVED** (Recovery Duration: 185 seconds)

- Ospf Neighbor Up
- Bgp Session Established
- Routes Relearned

#### 4.3.4  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Bgp Session Lost |
| **Root Trigger Event** | BGP peer 203.0.113.1 session lost |
| **Device** | WAN-Router-01 |
| **Causal Confidence** | 60% |
| **Causal Links Found** | 5 |

#### 4.3.5  Propagation

**Root Cause:** Bgp Session Lost on WAN-Router-01

**Propagation:**
Route Withdrawal -> Route Recalculation Started -> Route Recalculation Completed -> Recovery Completed

#### 4.3.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 09:05:00 | 31 | — | Warning | Bgp Session Lost | BGP peer 203.0.113.1 session lost |
| 2026-07-14 09:05:02 | 32 | — | Info | Route Withdrawal | Route withdrawal initiated for prefix 0.0.0.0/0 |
| 2026-07-14 09:05:05 | 33 | — | Warning | Ospf Neighbor Down | OSPF neighbor 10.99.0.1 changed state from FULL to DOWN |
| 2026-07-14 09:05:08 | 34 | — | Info | Route Recalculation Started | Routing table recalculation started |
| 2026-07-14 09:05:10 | 35 | — | Info | Route Recalculation Completed | Routing table recalculation completed |
| 2026-07-14 09:08:00 | 43 | — | Info | Ospf Neighbor Up | OSPF neighbor 10.99.0.1 changed state from DOWN to FULL |
| 2026-07-14 09:08:02 | 44 | — | Info | Bgp Session Established | BGP peer 203.0.113.1 session established |
| 2026-07-14 09:08:05 | 45 | — | Info | Routes Relearned | Routes successfully relearned |

#### 4.3.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Restore routing adjacency** | Verify physical connectivity and protocol timers on WAN-Router-01 |
| 2 | **Check interface stability** | Interface — may be causing routing instability |

---

### Incident INC-0009 — Ssh Bruteforce -> Ssh Source Blocked

> **Summary:** Repeated SSH authentication failures detected. Automatic source IP blocking was triggered. No successful authentication occurred before mitigation.

#### 4.4.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0009 |
| **Status** | Active |
| **Start Time** | 2026-07-14 09:07:02 UTC |
| **End Time** | 2026-07-14 09:07:06 UTC |
| **Duration** | 4.0s |
| **Severity** | Warning |
| **Affected Device** | Campus-Core-01 |
| **Affected Interface(s)** | — |
| **Events in Chain** | 2 |
| **Causal Confidence** | 60% |
| **Confidence Reasons** | ✓ Temporal proximity<br>✓ Known propagation chain |

#### 4.4.2  Timeline Reconstruction

```
2026-07-14 09:07:02 UTC
[WARNING]  Ssh Bruteforce
       SSH login failed from IP 10.99.99.5
        |
        v

2026-07-14 09:07:06 UTC
[CRITICAL]  Ssh Source Blocked
       SSH source 10.99.99.5 blocked after maximum failed attempts
```

#### 4.4.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Ssh Bruteforce |
| **Root Trigger Event** | SSH login failed from IP 10.99.99.5 |
| **Device** | Campus-Core-01 |
| **Causal Confidence** | 60% |
| **Causal Links Found** | 1 |

#### 4.4.4  Propagation

**Root Cause:** Ssh Bruteforce on Campus-Core-01

**Propagation:**
Ssh Bruteforce -> Ssh Source Blocked

#### 4.4.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 09:07:02 | 40 | — | Warning | Ssh Bruteforce | SSH login failed from IP 10.99.99.5 |
| 2026-07-14 09:07:06 | 42 | — | Critical | Ssh Source Blocked | SSH source 10.99.99.5 blocked after maximum failed attempts |

#### 4.4.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Block source IP at perimeter firewall** | External IP targeting management plane |
| 2 | **Enable SSH rate limiting** | Limit failed login attempts per source |
| 3 | **Review SSH access control list** | Restrict SSH to trusted management IPs only |

---

## 5. Standalone Alerts

> These events have **no proven causal chain**. Each is independent — not part of a cascading incident.

> No standalone alerts detected.

---

## 6. Operational Workflows

> These are **normal, successful operations** — not incidents.

| Workflow ID | Event Type | Time (UTC) | Status | Action Required |
|---|---|---|---|---|
| WORKFLOW-0002 | Config Change | 2026-07-14 09:00:05 | Successful | No |
| WORKFLOW-0008 | Config Change | 2026-07-14 09:06:10 | Successful | No |
| WORKFLOW-0008 | Config Change | 2026-07-14 09:09:20 | Successful | No |
| WORKFLOW-0013 | Authentication | 2026-07-14 09:09:30 | Successful | No |

---

## 7. Routine Informational Events

> These events are **not actionable**. Included for completeness only.

| Event Type | Time (UTC) | Device | Notes |
|---|---|---|---|
| Ntp | 2026-07-14 09:00:01 | Campus-Core-01 | Expected periodic time synchronization |
| Snmp | 2026-07-14 09:00:10 | Campus-Core-01 | Normal SNMP polling session teardown |
| Ntp | 2026-07-14 09:02:05 | Floor2-Access-01 | Expected periodic time synchronization |
| Dot1X Success | 2026-07-14 09:02:00 | Floor2-Access-01 | Classified as informational by causal engine |
| Dot1X Success | 2026-07-14 09:06:05 | Floor2-Access-01 | Classified as informational by causal engine |
| Interface Up | 2026-07-14 09:06:00 | Floor2-Access-01 | Standard port coming online |
| Lldp Neighbor Discovered | 2026-07-14 09:09:10 | Floor2-Access-01 | Expected neighbor discovery |
| Snmp | 2026-07-14 09:09:00 | Campus-Core-01 | Normal SNMP polling session teardown |
| Ntp | 2026-07-14 09:09:05 | Campus-Core-01 | Expected periodic time synchronization |
| Vlan | 2026-07-14 09:09:15 | Campus-Core-01 | Normal VLAN provisioning activity |
| Dot1X Success | 2026-07-14 09:09:25 | Floor3-Access-01 | Classified as informational by causal engine |

---

## 8. Recommendations

| Priority | Action | Source |
|---|---|---|
| High | Replace cable or transceiver | INC-0003 |
| High | Check port error counters | INC-0003 |
| High | Investigate root cause device and interface | INC-0005 |
| High | Add monitoring alerts for this event type | INC-0005 |
| High | Restore routing adjacency | INC-0006 |
| High | Check interface stability | INC-0006 |
| High | Block source IP at perimeter firewall | INC-0009 |
| High | Enable SSH rate limiting | INC-0009 |
| High | Review SSH access control list | INC-0009 |
| Low | Enrich device vendor metadata for improved classification accuracy | All |
| Low | Configure alerting for high root-score event subtypes | All |

---

## 9. Investigation Conclusion

**Reconstructed Incidents (4):**
- **INC-0003** — Root Cause: Crc Errors | Status: Resolved | Confidence: 75%
- **INC-0005** — Root Cause: Radius Failure | Status: Active | Confidence: N/A
- **INC-0006** — Root Cause: Bgp Session Lost | Status: Resolved | Confidence: 60%
- **INC-0009** — Root Cause: Ssh Bruteforce | Status: Active | Confidence: 60%

**Overall Network Health:** Poor — active incidents detected

**Remaining Uncertainties:**
- Causality is inferred from temporal and contextual heuristics — not guaranteed proof.
- Events with vendor = unknown may have reduced classification accuracy.

---

## 10. Appendix

| Field | Value |
|---|---|
| **Reconstructed Incident IDs** | INC-0003, INC-0005, INC-0006, INC-0009 |
| **Standalone Alert IDs** | None |
| **Total Causal Links** | 37 |
| **Report Generated** | 2026-07-14T17:53:15Z |
| **Log Reference Files** | normalized_events.json, timeline_output.json, causal_inference_output.json |
| **Causality Method** | Temporal + contextual heuristics (DAG-graph-partitioned) |
