# Network Incident Investigation Report

---

## 1. Executive Summary

| Field | Value |
|---|---|
| **Investigation Date** | 2026-07-14 |
| **Device(s) Analyzed** | Access-6200-02, Core-9300-01, Dist-6300-02, Edge-6300-01 |
| **Logs Analyzed** | 48 |
| **Reconstructed Incidents** | **4** — proven causal chain + RCA |
| **Standalone Alerts** | 0 |
| **Operational Workflows** | 6 |
| **Routine Informational Events** | 3 |
| **Highest Severity Observed** | Critical |
| **Overall Investigation Status** | Active — Unresolved incidents require immediate attention |

> **4 incident(s)** have a proven causal chain and receive full Root Cause Analysis below.
> The remaining 9 events are categorized as alerts (0), workflows (6), or routine (3) — none of these are incidents.

---

## 2. Investigation Scope

This investigation covers 48 log events collected from 4 device(s) (Access-6200-02, Core-9300-01, Dist-6300-02, Edge-6300-01) between 2026-07-14 08:00:01 UTC and 2026-07-14 08:09:25 UTC. A total of 4 incident(s) were reconstructed with full RCA, alongside 0 standalone alert(s), 6 operational workflow(s), and 3 routine informational event(s) — overall status: Active.

---

## 3. Incident Classification Summary

| Category | Count | IDs / Labels |
|---|---|---|
| Logs Analyzed | 48 | All parsed log events |
| **Reconstructed Incidents (RCA)** | **4** | INC-0003, INC-0005, INC-0007, INC-0008 |
| Standalone Alerts | 0 | None |
| Operational Workflows | 6 | WORKFLOW-0001, WORKFLOW-0002, WORKFLOW-0004, WORKFLOW-0009, WORKFLOW-0010, WORKFLOW-0011 |
| Routine Informational Events | 3 | Lldp, Interface Up, Vlan |

> **How to read this table:** Only Reconstructed Incidents have a proven causal chain.
> Standalone alerts, workflows, and routine events are **not incidents** — classified separately below.

---

## 4. Reconstructed Incidents — Full Root Cause Analysis

> Only **4** incident(s) below have a proven causal chain.
> Each section: Incident Overview (incl. impact) · Timeline · Root Cause · Cause-Effect Chain · Supporting Evidence · Recommendations

---

### Incident INC-0003 — Power Failure -> Fan Failure -> Thermal

#### 4.1.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0003 |
| **Status** | Active |
| **Start Time** | 2026-07-14 08:01:00 UTC |
| **End Time** | 2026-07-14 08:01:22 UTC |
| **Duration** | 22.0s |
| **Severity** | Critical |
| **Affected Device** | Core-9300-01 |
| **Affected Interface(s)** | 1/1/1, 1/1/2, 1/1/3 |
| **Events in Chain** | 12 |
| **Causal Confidence** | 75% |

#### 4.1.2  Timeline Reconstruction

```
2026-07-14 08:01:00 UTC
[CRITICAL]  Power Failure
       Power supply PSU-1 failure detected
        |
        v

2026-07-14 08:01:02 UTC
[WARNING]  Fan Failure
       Fan tray 2 speed out of normal range (High)
        |
        v

2026-07-14 08:01:04 UTC
[WARNING]  Thermal
       Internal temperature exceeded warning threshold (72C)
        |
        v

2026-07-14 08:01:06 UTC
[WARNING]  Thermal
       System entered thermal protection mode
        |
        v

2026-07-14 08:01:08 UTC
[CRITICAL]  Linecard Disabled
       Linecard slot 1 disabled due to thermal condition
        |
        v

2026-07-14 08:01:10 UTC
[INFO]  Interface Down
       Link down on interface 1/1/1
        |
        v

2026-07-14 08:01:11 UTC
[INFO]  Interface Down
       Link down on interface 1/1/2
        |
        v

2026-07-14 08:01:12 UTC
[INFO]  Interface Down
       Link down on interface 1/1/3
        |
        v

2026-07-14 08:01:14 UTC
[WARNING]  Ospf Neighbor Down
       OSPF neighbor 10.10.10.1 on interface 1/1/1 changed state from FULL to DOWN
        |
        v

2026-07-14 08:01:16 UTC
[WARNING]  Bgp Session Lost
       BGP peer 172.16.0.1 session lost
        |
        v

2026-07-14 08:01:20 UTC
[INFO]  Lldp
       LLDP neighbor removed from port 1/1/1
        |
        v

2026-07-14 08:01:22 UTC
[INFO]  Lldp
       LLDP neighbor removed from port 1/1/2
```

#### 4.1.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Power Failure |
| **Root Trigger Event** | Power supply PSU-1 failure detected |
| **Device** | Core-9300-01 |
| **Causal Confidence** | 75% |
| **Causal Links Found** | 32 |

#### 4.1.4  Cause-and-Effect Chain

```
Power Failure  <-- ROOT CAUSE
        |
        v
Fan Failure  (+2s)
        |
        v
Thermal  (+2s)
        |
        v
Linecard Disabled  (+4s)
        |
        v
Interface Down  (+2s)
        |
        v
Ospf Neighbor Down  (+4s)
        |
        v
Lldp  (+6s)
```

#### 4.1.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 08:01:00 | 4 | — | Critical | Power Failure | Power supply PSU-1 failure detected |
| 2026-07-14 08:01:02 | 5 | — | Warning | Fan Failure | Fan tray 2 speed out of normal range (High) |
| 2026-07-14 08:01:04 | 6 | — | Warning | Thermal | Internal temperature exceeded warning threshold (72C) |
| 2026-07-14 08:01:06 | 7 | — | Warning | Thermal | System entered thermal protection mode |
| 2026-07-14 08:01:08 | 8 | — | Critical | Linecard Disabled | Linecard slot 1 disabled due to thermal condition |
| 2026-07-14 08:01:10 | 9 | 1/1/1 | Info | Interface Down | Link down on interface 1/1/1 |
| 2026-07-14 08:01:11 | 10 | 1/1/2 | Info | Interface Down | Link down on interface 1/1/2 |
| 2026-07-14 08:01:12 | 11 | 1/1/3 | Info | Interface Down | Link down on interface 1/1/3 |
| 2026-07-14 08:01:14 | 12 | 1/1/1 | Warning | Ospf Neighbor Down | OSPF neighbor 10.10.10.1 on interface 1/1/1 changed state from FULL to DOWN |
| 2026-07-14 08:01:16 | 13 | — | Warning | Bgp Session Lost | BGP peer 172.16.0.1 session lost |
| 2026-07-14 08:01:20 | 14 | 1/1/1 | Info | Lldp | LLDP neighbor removed from port 1/1/1 |
| 2026-07-14 08:01:22 | 15 | 1/1/2 | Info | Lldp | LLDP neighbor removed from port 1/1/2 |

#### 4.1.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Replace failed power supply immediately** | No power redundancy — one PSU left |
| 2 | **Monitor thermal sensors** | Fan overspeed may indicate thermal stress |
| 3 | **Schedule emergency maintenance** | On-site hardware replacement required |

---

### Incident INC-0005 — Transceiver -> Interface Down

#### 4.2.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0005 |
| **Status** | Resolved |
| **Start Time** | 2026-07-14 08:03:00 UTC |
| **End Time** | 2026-07-14 08:09:25 UTC |
| **Duration** | 385.0s |
| **Severity** | Info |
| **Affected Device** | Dist-6300-02 |
| **Affected Interface(s)** | 1/1/49 |
| **Events in Chain** | 17 |
| **Causal Confidence** | 64% |

#### 4.2.2  Timeline Reconstruction

```
2026-07-14 08:03:00 UTC
[INFO]  Transceiver
       Transceiver on port 1/1/49 removed or signal lost
        |
        v

2026-07-14 08:03:01 UTC
[INFO]  Interface Down
       Link down on interface 1/1/49
        |
        v

2026-07-14 08:03:02 UTC
[INFO]  Interface Down
       Interface 1/1/49 operational status changed to DOWN
        |
        v

2026-07-14 08:03:03 UTC
[INFO]  Ospf Interface Down
       OSPF interface 1/1/49 state changed from PtP to Down
        |
        v

2026-07-14 08:03:04 UTC
[WARNING]  Ospf Neighbor Down
       OSPF neighbor 10.20.20.1 changed state from FULL to DOWN
        |
        v

2026-07-14 08:03:06 UTC
[INFO]  Route Recalculation Started
       Routing table recalculation started
        |
        v

2026-07-14 08:03:07 UTC
[INFO]  Route Recalculation Completed
       Routing table recalculation completed
        |
        v

2026-07-14 08:03:09 UTC
[WARNING]  Bgp Session Lost
       BGP peer 172.16.2.1 session lost
        |
        v

2026-07-14 08:03:12 UTC
[INFO]  Route Withdrawal
       Route withdrawal initiated for prefix 10.20.0.0/16
        |
        v

2026-07-14 08:07:00 UTC
[INFO]  Transceiver  <- RECOVERY
       Transceiver inserted on port 1/1/49
        |
        v

2026-07-14 08:07:01 UTC
[INFO]  Interface Up  <- RECOVERY
       Link up on interface 1/1/49
        |
        v

2026-07-14 08:07:02 UTC
[INFO]  Interface Up  <- RECOVERY
       Interface 1/1/49 operational status changed to UP
        |
        v

2026-07-14 08:07:03 UTC
[INFO]  Ospf Interface Up  <- RECOVERY
       OSPF interface 1/1/49 state changed from Down to PtP
        |
        v

2026-07-14 08:07:04 UTC
[INFO]  Ospf Neighbor Up  <- RECOVERY
       OSPF neighbor 10.20.20.1 changed state from DOWN to FULL
        |
        v

2026-07-14 08:07:06 UTC
[INFO]  Bgp Session Established  <- RECOVERY
       BGP peer 172.16.2.1 session established
        |
        v

2026-07-14 08:07:08 UTC
[INFO]  Routes Relearned  <- RECOVERY
       Routes successfully relearned
        |
        v

2026-07-14 08:09:25 UTC
[INFO]  Lldp
       LLDP neighbor discovered on port 1/1/49
```

#### 4.2.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Transceiver |
| **Root Trigger Event** | Transceiver on port 1/1/49 removed or signal lost |
| **Device** | Dist-6300-02 |
| **Causal Confidence** | 64% |
| **Causal Links Found** | 22 |

#### 4.2.4  Cause-and-Effect Chain

```
Transceiver  <-- ROOT CAUSE
        |
        v
Interface Down  (+1s)
        |
        v
Interface Down  (+1s)
        |
        v
Ospf Interface Down  (+1s)
        |
        v
Route Recalculation Started  (+3s)
        |
        v
Route Recalculation Completed  (+1s)
        |
        v
Bgp Session Lost  (+2s)
        |
        v
Route Withdrawal  (+3s)
```

#### 4.2.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 08:03:00 | 18 | 1/1/49 | Info | Transceiver | Transceiver on port 1/1/49 removed or signal lost |
| 2026-07-14 08:03:01 | 19 | 1/1/49 | Info | Interface Down | Link down on interface 1/1/49 |
| 2026-07-14 08:03:02 | 20 | 1/1/49 | Info | Interface Down | Interface 1/1/49 operational status changed to DOWN |
| 2026-07-14 08:03:03 | 21 | 1/1/49 | Info | Ospf Interface Down | OSPF interface 1/1/49 state changed from PtP to Down |
| 2026-07-14 08:03:04 | 22 | — | Warning | Ospf Neighbor Down | OSPF neighbor 10.20.20.1 changed state from FULL to DOWN |
| 2026-07-14 08:03:06 | 23 | — | Info | Route Recalculation Started | Routing table recalculation started |
| 2026-07-14 08:03:07 | 24 | — | Info | Route Recalculation Completed | Routing table recalculation completed |
| 2026-07-14 08:03:09 | 25 | — | Warning | Bgp Session Lost | BGP peer 172.16.2.1 session lost |
| 2026-07-14 08:03:12 | 26 | — | Info | Route Withdrawal | Route withdrawal initiated for prefix 10.20.0.0/16 |
| 2026-07-14 08:07:00 | 40 | 1/1/49 | Info | Transceiver | Transceiver inserted on port 1/1/49 |
| 2026-07-14 08:07:01 | 41 | 1/1/49 | Info | Interface Up | Link up on interface 1/1/49 |
| 2026-07-14 08:07:02 | 42 | 1/1/49 | Info | Interface Up | Interface 1/1/49 operational status changed to UP |
| 2026-07-14 08:07:03 | 43 | 1/1/49 | Info | Ospf Interface Up | OSPF interface 1/1/49 state changed from Down to PtP |
| 2026-07-14 08:07:04 | 44 | — | Info | Ospf Neighbor Up | OSPF neighbor 10.20.20.1 changed state from DOWN to FULL |
| 2026-07-14 08:07:06 | 45 | — | Info | Bgp Session Established | BGP peer 172.16.2.1 session established |
| 2026-07-14 08:07:08 | 46 | — | Info | Routes Relearned | Routes successfully relearned |
| 2026-07-14 08:09:25 | 54 | 1/1/49 | Info | Lldp | LLDP neighbor discovered on port 1/1/49 |

#### 4.2.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Investigate root cause device and interface** | device=Dist-6300-02, interface=1/1/49 |
| 2 | **Add monitoring alerts for this event type** | subtype=transceiver |

---

### Incident INC-0007 — Ssh Bruteforce -> Ssh Source Blocked

#### 4.3.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0007 |
| **Status** | Active |
| **Start Time** | 2026-07-14 08:04:00 UTC |
| **End Time** | 2026-07-14 08:04:08 UTC |
| **Duration** | 8.0s |
| **Severity** | Warning |
| **Affected Device** | Edge-6300-01 |
| **Affected Interface(s)** | — |
| **Events in Chain** | 2 |
| **Causal Confidence** | 60% |

#### 4.3.2  Timeline Reconstruction

```
2026-07-14 08:04:00 UTC
[WARNING]  Ssh Bruteforce
       SSH login failed from IP 198.51.100.45
        |
        v

2026-07-14 08:04:08 UTC
[CRITICAL]  Ssh Source Blocked
       SSH source 198.51.100.45 blocked after maximum failed attempts
```

#### 4.3.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Ssh Bruteforce |
| **Root Trigger Event** | SSH login failed from IP 198.51.100.45 |
| **Device** | Edge-6300-01 |
| **Causal Confidence** | 60% |
| **Causal Links Found** | 1 |

#### 4.3.4  Cause-and-Effect Chain

```
Ssh Bruteforce  <-- ROOT CAUSE
        |
        v
Ssh Source Blocked  (+8s)
```

#### 4.3.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 08:04:00 | 28 | — | Warning | Ssh Bruteforce | SSH login failed from IP 198.51.100.45 |
| 2026-07-14 08:04:08 | 32 | — | Critical | Ssh Source Blocked | SSH source 198.51.100.45 blocked after maximum failed attempts |

#### 4.3.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Block source IP at perimeter firewall** | External IP targeting management plane |
| 2 | **Enable SSH rate limiting** | Limit failed login attempts per source |
| 3 | **Review SSH access control list** | Restrict SSH to trusted management IPs only |

---

### Incident INC-0008 — Dot1X Failure -> Radius Failure -> Port Blocked

#### 4.4.1  Incident Overview

| Field | Value |
|---|---|
| **Incident ID** | INC-0008 |
| **Status** | Active |
| **Start Time** | 2026-07-14 08:05:00 UTC |
| **End Time** | 2026-07-14 08:09:20 UTC |
| **Duration** | 260.0s |
| **Severity** | Error |
| **Affected Device** | Access-6200-02 |
| **Affected Interface(s)** | 1/1/8 |
| **Events in Chain** | 5 |
| **Causal Confidence** | 0% |

#### 4.4.2  Timeline Reconstruction

```
2026-07-14 08:05:00 UTC
[ERROR]  Dot1X Failure
       802.1x: Authentication failed for client DD:EE:FF:00:11:22 on port 1/1/8
        |
        v

2026-07-14 08:05:10 UTC
[ERROR]  Radius Failure
       RADIUS server 10.0.0.100 unreachable, authentication timeout
        |
        v

2026-07-14 08:05:15 UTC
[WARNING]  Port Blocked
       Port 1/1/8 blocked due to repeated authentication failures
        |
        v

2026-07-14 08:08:00 UTC
[INFO]  Authentication
       SSH access granted for user admin from 10.0.0.50
        |
        v

2026-07-14 08:09:20 UTC
[INFO]  Mac Auth
       MAC Authentication successful for client EE:FF:00:33:44:55
```

#### 4.4.3  Root Cause Analysis

| Field | Detail |
|---|---|
| **Root Cause** | Dot1X Failure |
| **Root Trigger Event** | 802.1x: Authentication failed for client DD:EE:FF:00:11:22 on port 1/1/8 |
| **Device** | Access-6200-02 |
| **Causal Confidence** | 0% |
| **Causal Links Found** | 4 |

#### 4.4.5  Supporting Evidence

| Time (UTC) | UID | Interface | Severity | Event Type | Log Message |
|---|---|---|---|---|---|
| 2026-07-14 08:05:00 | 33 | 1/1/8 | Error | Dot1X Failure | 802.1x: Authentication failed for client DD:EE:FF:00:11:22 on port 1/1/8 |
| 2026-07-14 08:05:10 | 36 | — | Error | Radius Failure | RADIUS server 10.0.0.100 unreachable, authentication timeout |
| 2026-07-14 08:05:15 | 37 | 1/1/8 | Warning | Port Blocked | Port 1/1/8 blocked due to repeated authentication failures |
| 2026-07-14 08:08:00 | 47 | — | Info | Authentication | SSH access granted for user admin from 10.0.0.50 |
| 2026-07-14 08:09:20 | 53 | — | Info | Mac Auth | MAC Authentication successful for client EE:FF:00:33:44:55 |

#### 4.4.6  Recommendations

| # | Action | Rationale |
|---|---|---|
| 1 | **Review NAC/802.1X policy** | Authentication failure may indicate unauthorized device |
| 2 | **Audit recent login attempts** | Check if failure is a misconfigured client or attack |

---

## 5. Standalone Alerts

> These events have **no proven causal chain**. Each is independent — not part of a cascading incident.

> No standalone alerts detected.

---

## 6. Operational Workflows

> These are **normal, successful operations** — not incidents.

| Workflow ID | Event Type | Time (UTC) | Status | Action Required |
|---|---|---|---|---|
| WORKFLOW-0001 | Ntp | 2026-07-14 08:00:01 | Successful | No |
| WORKFLOW-0001 | Snmp | 2026-07-14 08:00:05 | Successful | No |
| WORKFLOW-0001 | Ntp | 2026-07-14 08:02:05 | Successful | No |
| WORKFLOW-0001 | Snmp | 2026-07-14 08:06:00 | Successful | No |
| WORKFLOW-0002 | Config Change | 2026-07-14 08:00:10 | Successful | No |
| WORKFLOW-0004 | Mac Auth | 2026-07-14 08:02:00 | Successful | No |
| WORKFLOW-0009 | Config Change | 2026-07-14 08:06:05 | Successful | No |
| WORKFLOW-0010 | Config Change | 2026-07-14 08:08:05 | Successful | No |
| WORKFLOW-0011 | Mac Auth | 2026-07-14 08:09:00 | Successful | No |

---

## 7. Routine Informational Events

> These events are **not actionable**. Included for completeness only.

| Event Type | Time (UTC) | Device | Notes |
|---|---|---|---|
| Lldp | 2026-07-14 08:03:30 | Access-6200-01 | Expected neighbor discovery |
| Interface Up | 2026-07-14 08:09:05 | Access-6200-01 | Standard port coming online |
| Vlan | 2026-07-14 08:09:15 | Core-9300-01 | Normal VLAN provisioning activity |

---

## 8. Recommendations

| Priority | Action | Source |
|---|---|---|
| Critical | Replace failed power supply immediately | INC-0003 |
| Critical | Monitor thermal sensors | INC-0003 |
| Critical | Schedule emergency maintenance | INC-0003 |
| Medium | Investigate root cause device and interface | INC-0005 |
| Medium | Add monitoring alerts for this event type | INC-0005 |
| High | Block source IP at perimeter firewall | INC-0007 |
| High | Enable SSH rate limiting | INC-0007 |
| High | Review SSH access control list | INC-0007 |
| High | Review NAC/802.1X policy | INC-0008 |
| High | Audit recent login attempts | INC-0008 |
| Low | Enrich device vendor metadata for improved classification accuracy | All |
| Low | Configure alerting for high root-score event subtypes | All |

---

## 9. Investigation Conclusion

**Reconstructed Incidents (4):**
- **INC-0003** — Root Cause: Power Failure | Status: Active | Confidence: 75%
- **INC-0005** — Root Cause: Transceiver | Status: Resolved | Confidence: 64%
- **INC-0007** — Root Cause: Ssh Bruteforce | Status: Active | Confidence: 60%
- **INC-0008** — Root Cause: Dot1X Failure | Status: Active | Confidence: N/A

**Overall Network Health:** Poor — active incidents detected

**Remaining Uncertainties:**
- Causality is inferred from temporal and contextual heuristics — not guaranteed proof.
- Events with vendor = unknown may have reduced classification accuracy.

---

## 10. Appendix

| Field | Value |
|---|---|
| **Reconstructed Incident IDs** | INC-0003, INC-0005, INC-0007, INC-0008 |
| **Standalone Alert IDs** | None |
| **Total Causal Links** | 59 |
| **Report Generated** | 2026-07-14T17:28:04Z |
| **Log Reference Files** | normalized_events.json, timeline_output.json, causal_inference_output.json |
| **Causality Method** | Temporal + contextual heuristics (DAG-graph-partitioned) |
