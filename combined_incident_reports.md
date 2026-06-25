
============================================================
=== final_demo.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:25:48Z

## Executive Summary
- Total incidents reconstructed: 5
- Total events analyzed: 45
- Total causal links inferred: 36
- Affected devices: Access-6100-02, Access-6100-03, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0004 -> transceiver (device=Dist-6300-01, score=192.2)
- Incident INC-0006 -> dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0007 -> power_failure (device=Core-8325-01, score=218.8)
- Incident INC-0008 -> crc_errors (device=Access-6100-03, score=188.9)

## Incident Overview
- INC-0004: events=16, duration=190.0s, primary_issue=transceiver
- INC-0005: events=2, duration=4.0s, primary_issue=ssh_bruteforce
- INC-0006: events=2, duration=6.0s, primary_issue=dot1x_failure
- INC-0007: events=7, duration=65.0s, primary_issue=power_failure
- INC-0008: events=4, duration=10.0s, primary_issue=crc_errors

## Detailed Incident Chains
### INC-0004
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)
- bgp_session_lost (warning)
- route_withdrawal (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- interface_up (info)
- ospf_interface_up (info)
- ospf_neighbor_up (info)
- bgp_session_established (info)
- routes_relearned (info)

*Status: Resolved*
*Duration: 190.0s*

### INC-0005
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 4.0s*

### INC-0006
**Failure Sequence:**
- dot1x_failure ×3 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 6.0s*

### INC-0007
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)
- linecard_disabled (critical)
- bgp_session_lost (warning)
- lldp (info)

*Status: Active*
*Duration: 65.0s*

### INC-0008
**Failure Sequence:**
- crc_errors ×2 (warning)
- interface_down (info)
- interface_down (info)
- lldp (info)

*Status: Active*
*Duration: 10.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0001
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - ntp (info)
  - snmp (info)
  - ntp (info)
  - snmp (info)

### Workflow: WORKFLOW-0002
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)
  - raw (info) x2

### Workflow: WORKFLOW-0003
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info) x2

### Workflow: WORKFLOW-0010
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- Core-8325-01: vlan (info) - VLAN 200 created
- Access-6100-01: lldp (info) - LLDP neighbor discovered on port 1/1/12
- Access-6100-04: interface_up (info) - Port 1/1/20 is now on-line
- Access-6100-04: interface_up (info) - Port 1/1/21 is now on-line

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== logs.txt ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:25:51Z

## Executive Summary
- Total incidents reconstructed: 6
- Total events analyzed: 20
- Total causal links inferred: 4
- Affected devices: 192.168.1.104

## Probable Initiating Triggers
- Incident INC-0011 -> stp_topology_change (device=192.168.1.104, score=93.6)
- Incident INC-0013 -> power_failure (device=192.168.1.104, score=217.3)

## Incident Overview
- INC-0011: events=4, duration=188.0s, primary_issue=stp_topology_change
- INC-0013: events=2, duration=89.0s, primary_issue=power_failure
- INC-0004: events=1, duration=0.0s, primary_issue=dot1x_failure
- INC-0005: events=3, duration=145.0s, primary_issue=crc_errors
- INC-0009: events=1, duration=0.0s, primary_issue=admin_auth_failure
- INC-0010: events=1, duration=0.0s, primary_issue=ssh_bruteforce

## Detailed Incident Chains
### INC-0011
**Failure Sequence:**
- stp_topology_change (info)
- stp_topology_change (warning)
- ospf_neighbor_down (warning)

**Recovery Sequence:**
- bgp_session_established (info)

*Status: Recovering*
*Duration: 188.0s*

### INC-0013
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)

*Status: Active*
*Duration: 89.0s*

### INC-0004
**Failure Sequence:**
- dot1x_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0005
**Failure Sequence:**
- interface_down (info)
- crc_errors (warning)

**Recovery Sequence:**
- transceiver (info)

*Status: Active*
*Duration: 145.0s*

### INC-0009
**Failure Sequence:**
- admin_auth_failure (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0010
**Failure Sequence:**
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0007
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info)

### Workflow: WORKFLOW-0012
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.104: dot1x_failure (error) - 802.1x: Authentication failed for client 00:11:22:33:44:55 on port 1/1/5
- 192.168.1.104: interface_down (info) - Port 1/1/2 is now off-line
- 192.168.1.104: crc_errors (warning) - Port 1/1/12: Excessive CRC errors detected
- 192.168.1.104: transceiver (info) - Transceiver inserted in port 1/1/48
- 192.168.1.104: admin_auth_failure (warning) - Authentication failure for user admin from 192.168.1.99
- 192.168.1.104: ssh_bruteforce (critical) - SSH login failed from IP 203.0.113.5: Maximum attempts exceeded

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.104: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.104: interface_up (info) - Port 1/1/1 is now on-line
- 192.168.1.104: vlan (info) - Vlan 10 is created
- 192.168.1.104: lldp (info) - LLDP neighbor 00:25:B3:11:22:33 discovered on port 1/1/10
- 192.168.1.104: dot1x_logout (info) - 802.1x: Client 00:11:22:33:44:55 logged out from port 1/1/5
- 192.168.1.104: ntp (info) - NTP synchronized to time server 132.163.97.5

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== single_test.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:25:53Z

## Executive Summary
- Total incidents reconstructed: 5
- Total events analyzed: 24
- Total causal links inferred: 16
- Affected devices: 192.168.1.10

## Probable Initiating Triggers
- Incident INC-0007 -> interface_down (device=192.168.1.10, score=178.0)
- Incident INC-0010 -> power_failure (device=192.168.1.10, score=218.2)

## Incident Overview
- INC-0006: events=5, duration=64.0s, primary_issue=ssh_bruteforce
- INC-0007: events=2, duration=47.0s, primary_issue=interface_down
- INC-0010: events=5, duration=89.0s, primary_issue=power_failure
- INC-0005: events=1, duration=0.0s, primary_issue=dot1x_failure
- INC-0011: events=1, duration=0.0s, primary_issue=dot1x_failure

## Detailed Incident Chains
### INC-0006
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 64.0s*

### INC-0007
**Failure Sequence:**
- interface_down (info)
- crc_errors (warning)

*Status: Active*
*Duration: 47.0s*

### INC-0010
**Failure Sequence:**
- power_failure (critical)
- interface_down (critical)
- interface_down (critical)
- stp_topology_change (warning)
- fan_failure (warning)

*Status: Active*
*Duration: 89.0s*

### INC-0005
**Failure Sequence:**
- dot1x_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0011
**Failure Sequence:**
- dot1x_failure (error)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0008
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)

### Workflow: WORKFLOW-0014
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.10: dot1x_failure (error) - 802.1x: Authentication failed for client 00:11:22:33:44:55 on port 1/1/5
- 192.168.1.10: dot1x_failure (error) - 802.1x: Authentication failed for client AA:BB:CC:DD:EE:FF on port 1/1/8

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.012ms
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: interface_up (info) - Port 1/1/9 is now on-line
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/1: remote device router-1 (10.0.0.2)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/3: remote device switch-2 (10.0.0.4)
- 192.168.1.10: bgp_session_established (info) - BGP peer 10.0.0.2 session established
- 192.168.1.10: interface_up (info) - Port 1/1/1 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/2 is now on-line

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test2.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:25:57Z

## Executive Summary
- Total incidents reconstructed: 5
- Total events analyzed: 40
- Total causal links inferred: 31
- Affected devices: 192.168.1.10

## Probable Initiating Triggers
- Incident INC-0010 -> crc_errors (device=192.168.1.10, score=190.1)
- Incident INC-0011 -> dot1x_failure (device=192.168.1.10, score=55.8)

## Incident Overview
- INC-0010: events=8, duration=181.0s, primary_issue=crc_errors
- INC-0011: events=7, duration=48.0s, primary_issue=dot1x_failure
- INC-0021: events=3, duration=40.0s, primary_issue=ssh_bruteforce
- INC-0007: events=1, duration=0.0s, primary_issue=standalone_alert
- INC-0014: events=2, duration=135.0s, primary_issue=stp_topology_change

## Detailed Incident Chains
### INC-0010
**Failure Sequence:**
- crc_errors (warning)
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)
- bgp (warning)
- ospf_neighbor_down (warning)

*Status: Active*
*Duration: 181.0s*

### INC-0011
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)
- dot1x_failure (error)

*Status: Active*
*Duration: 48.0s*

### INC-0021
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 40.0s*

### INC-0007
**Failure Sequence:**
- raw (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0014
**Failure Sequence:**
- bgp_session_lost (critical)
- stp_topology_change (info)

*Status: Active*
*Duration: 135.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0008
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info) x2

### Workflow: WORKFLOW-0009
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0012
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_down (info)

### Workflow: WORKFLOW-0019
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)
  - bgp_session_established (info)
  - ospf_neighbor_up (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15
- 192.168.1.10: bgp_session_lost (critical) - BGP peer 10.0.0.6 session Down, hold timer expired
- 192.168.1.10: stp_topology_change (info) - Instance 0: Topology converged, root bridge unchanged

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.008ms
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/1: remote device router-1 (10.0.0.2)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/2: remote device router-2 (10.0.0.6)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/4: remote device switch-3 (10.0.0.9)
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: fan_nominal (warning) - Fan tray 2 speed nominal
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client AA:11:BB:22:CC:33 on port 1/1/40 (backup RADIUS)
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client BB:22:CC:33:DD:44 on port 1/1/41 (backup RADIUS)
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/8 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test3.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:25:58Z

## Executive Summary
- Total incidents reconstructed: 4
- Total events analyzed: 10
- Total causal links inferred: 0
- Affected devices: N/A

## Probable Initiating Triggers
- No high-confidence root trigger was detected

## Incident Overview
- INC-0003: events=2, duration=40.0s, primary_issue=ospf
- INC-0004: events=1, duration=0.0s, primary_issue=bgp
- INC-0006: events=2, duration=245.0s, primary_issue=bgp
- INC-0007: events=1, duration=0.0s, primary_issue=temperature

## Detailed Incident Chains
### INC-0003

**Recovery Sequence:**
- bgp (warning)
- ospf (warning)

*Status: Active*
*Duration: 40.0s*

### INC-0004
**Failure Sequence:**
- bgp (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0006

**Recovery Sequence:**
- bgp (warning)
- ospf (info)

*Status: Active*
*Duration: 245.0s*

### INC-0007
**Failure Sequence:**
- temperature (warning)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0002
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - authentication (info)

### Workflow: WORKFLOW-0005
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - power (info)

### Workflow: WORKFLOW-0008
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - authentication (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- router-2: bgp (warning) - rpd[1190]: [daemon.warning] BGP_NEIGHBOR_STATE_CHANGED: bgp peer 192.168.1.10 state changed from Established to Active
- router-2: ospf (warning) - rpd[1190]: [daemon.info] RPD_OSPF_NBRDOWN: OSPF neighbor 192.168.3.1 on ge-0/0/2.0 state changed from Full to Down
- router-2: bgp (warning) - rpd[1190]: [daemon.warning] BGP_NEIGHBOR_STATE_CHANGED: bgp peer 192.168.1.10 state changed from Active to Idle, hold timer expired
- router-2: bgp (warning) - rpd[1190]: [daemon.info] BGP_NEIGHBOR_STATE_CHANGED: bgp peer 192.168.1.10 state changed from Idle to Established
- router-2: ospf (info) - rpd[1190]: [daemon.info] RPD_OSPF_NBRUP: OSPF neighbor 192.168.3.1 on ge-0/0/2.0 state changed from Down to Full
- router-2: temperature (warning) - chassisd[330]: [hw.warn] Temperature sensor 1 reading elevated: 52C (threshold 65C)

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- router-2: lldp (info) - rpd[1190]: [daemon.info] LLDP neighbor core-switch (10.0.0.6) discovered on ge-0/0/1

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test4.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:00Z

## Executive Summary
- Total incidents reconstructed: 3
- Total events analyzed: 15
- Total causal links inferred: 10
- Affected devices: 192.168.1.10

## Probable Initiating Triggers
- Incident INC-0003 -> crc_errors (device=192.168.1.10, score=189.2)
- Incident INC-0005 -> dot1x_failure (device=192.168.1.10, score=54.9)

## Incident Overview
- INC-0003: events=5, duration=73.0s, primary_issue=crc_errors
- INC-0005: events=4, duration=28.0s, primary_issue=dot1x_failure
- INC-0004: events=1, duration=0.0s, primary_issue=standalone_alert

## Detailed Incident Chains
### INC-0003
**Failure Sequence:**
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)

*Status: Active*
*Duration: 73.0s*

### INC-0005
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)

*Status: Active*
*Duration: 28.0s*

### INC-0004
**Failure Sequence:**
- raw (warning)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0008
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - power (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.005ms
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/9 is now on-line

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test5.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:02Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 7
- Total causal links inferred: 16
- Affected devices: Edge-6300-01

## Probable Initiating Triggers
- Incident INC-0001 -> transceiver (device=Edge-6300-01, score=189.5)

## Incident Overview
- INC-0001: events=7, duration=0.024s, primary_issue=transceiver

## Detailed Incident Chains
### INC-0001
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- ospf (info)
- ospf (info)

*Status: Active*
*Duration: 0.024s*

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test6.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:05Z

## Executive Summary
- Total incidents reconstructed: 6
- Total events analyzed: 50
- Total causal links inferred: 42
- Affected devices: 192.168.1.10

## Probable Initiating Triggers
- Incident INC-0010 -> crc_errors (device=192.168.1.10, score=190.1)
- Incident INC-0018 -> crc_errors (device=192.168.1.10, score=189.5)
- Incident INC-0022 -> dot1x_failure (device=192.168.1.10, score=55.8)

## Incident Overview
- INC-0010: events=8, duration=181.0s, primary_issue=crc_errors
- INC-0018: events=6, duration=120.0s, primary_issue=crc_errors
- INC-0022: events=7, duration=48.0s, primary_issue=dot1x_failure
- INC-0025: events=3, duration=40.0s, primary_issue=ssh_bruteforce
- INC-0007: events=1, duration=0.0s, primary_issue=standalone_alert
- INC-0013: events=1, duration=0.0s, primary_issue=bgp_session_lost

## Detailed Incident Chains
### INC-0010
**Failure Sequence:**
- crc_errors (warning)
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)
- bgp (warning)
- ospf_neighbor_down (warning)

*Status: Active*
*Duration: 181.0s*

### INC-0018
**Failure Sequence:**
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)
- ospf_neighbor_down (warning)

*Status: Active*
*Duration: 120.0s*

### INC-0022
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)
- dot1x_failure (error)

*Status: Active*
*Duration: 48.0s*

### INC-0025
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 40.0s*

### INC-0007
**Failure Sequence:**
- raw (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0013
**Failure Sequence:**
- bgp_session_lost (critical)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0008
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info) x2

### Workflow: WORKFLOW-0009
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0011
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_down (info)

### Workflow: WORKFLOW-0016
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)
  - bgp_session_established (info)
  - ospf_neighbor_up (info)

### Workflow: WORKFLOW-0021
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)
  - ospf_neighbor_up (info)

### Workflow: WORKFLOW-0026
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - power (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15
- 192.168.1.10: bgp_session_lost (critical) - BGP peer 10.0.0.6 session Down, hold timer expired

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.006ms
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/1: remote device router-1 (10.0.0.2)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/2: remote device router-2 (10.0.0.6)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/4: remote device switch-3 (10.0.0.9)
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: fan_nominal (warning) - Fan tray 2 speed nominal
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/8 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/55 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/56 is now on-line
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client AA:11:BB:22:CC:33 on port 1/1/40 (backup RADIUS)
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client BB:22:CC:33:DD:44 on port 1/1/41 (backup RADIUS)

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test7.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:08Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 10
- Total causal links inferred: 23
- Affected devices: Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0001 -> transceiver (device=Dist-6300-01, score=190.4)

## Incident Overview
- INC-0001: events=10, duration=9.0s, primary_issue=transceiver

## Detailed Incident Chains
### INC-0001
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)
- bgp_session_lost (warning)
- route_withdrawal (info)
- routes_withdrawn (info)

*Status: Active*
*Duration: 9.0s*

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_cascade.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:10Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 9
- Total causal links inferred: 19
- Affected devices: 192.168.1.104

## Probable Initiating Triggers
- Incident INC-0001 -> transceiver (device=192.168.1.104, score=190.1)

## Incident Overview
- INC-0001: events=9, duration=9.0s, primary_issue=transceiver

## Detailed Incident Chains
### INC-0001
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)
- bgp_session_lost (warning)
- route_withdrawal (info)

*Status: Active*
*Duration: 9.0s*

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_demo.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:12Z

## Executive Summary
- Total incidents reconstructed: 4
- Total events analyzed: 30
- Total causal links inferred: 27
- Affected devices: Access-6100-04, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0003 -> transceiver (device=Dist-6300-01, score=190.4)
- Incident INC-0004 -> dot1x_failure (device=Access-6100-04, score=54.3)
- Incident INC-0005 -> power_failure (device=Core-8325-01, score=217.9)

## Incident Overview
- INC-0003: events=10, duration=8.614s, primary_issue=transceiver
- INC-0004: events=2, duration=2.086s, primary_issue=dot1x_failure
- INC-0005: events=4, duration=14.433s, primary_issue=power_failure
- INC-0006: events=2, duration=1.229s, primary_issue=ssh_bruteforce

## Detailed Incident Chains
### INC-0003
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- ospf (info)
- ospf (info)
- bgp_session_lost (warning)
- route_withdrawal (info)
- route_withdrawal (info)

*Status: Active*
*Duration: 8.614s*

### INC-0004
**Failure Sequence:**
- dot1x_failure ×3 (error)
- raw (warning)

*Status: Active*
*Duration: 2.086s*

### INC-0005
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)

*Status: Active*
*Duration: 14.433s*

### INC-0006
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 1.229s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0001
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)
  - lldp (info)

### Workflow: WORKFLOW-0007
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - transceiver (info)
  - interface_up (info) x2
  - ospf_interface_up (info)
  - ospf_neighbor_up (info)
  - bgp_session_established (info)
  - routes_relearned (info)

### Workflow: WORKFLOW-0009
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- Core-8325-01: vlan (info) - VLAN 100 created
- Core-8325-01: ntp (info) - NTP synchronized with time source 192.168.1.1

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_general.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:15Z

## Executive Summary
- Total incidents reconstructed: 4
- Total events analyzed: 19
- Total causal links inferred: 17
- Affected devices: Access-6100-02, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0002 -> transceiver (device=Dist-6300-01, score=197.8)
- Incident INC-0004 -> dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0005 -> power_failure (device=Core-8325-01, score=217.9)

## Incident Overview
- INC-0002: events=7, duration=241.0s, primary_issue=transceiver
- INC-0003: events=4, duration=15.0s, primary_issue=ssh_bruteforce
- INC-0004: events=2, duration=8.0s, primary_issue=dot1x_failure
- INC-0005: events=4, duration=25.0s, primary_issue=power_failure

## Detailed Incident Chains
### INC-0002
**Failure Sequence:**
- transceiver (warning)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (warning)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- ospf_neighbor_up (info)

*Status: Resolved*
*Duration: 241.0s*

### INC-0003
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 15.0s*

### INC-0004
**Failure Sequence:**
- dot1x_failure ×2 (error)
- raw (warning)

*Status: Active*
*Duration: 8.0s*

### INC-0005
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (critical)

*Status: Active*
*Duration: 25.0s*

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- Core-8325-01: ntp (info) - Synchronized to NTP server 10.0.0.1
- Core-8325-01: snmp (info) - Connection with 192.168.1.50 closed

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_logs.txt ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:17Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 11
- Total causal links inferred: 9
- Affected devices: router-1

## Probable Initiating Triggers
- Incident INC-0004 -> interface_down (device=router-1, score=195.2)

## Incident Overview
- INC-0004: events=5, duration=146.0s, primary_issue=interface_down

## Detailed Incident Chains
### INC-0004
**Failure Sequence:**
- interface_down (error)
- interface_down (info)
- bgp (info)
- ospf_neighbor_down (info)
- ospf_neighbor_down (info)

*Status: Active*
*Duration: 146.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0001
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0003
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - bgp (info)

### Workflow: WORKFLOW-0006
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - bgp (info)

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- router-1: lldp (info) - %LLDP-5-NEIGHBOR: LLDP neighbor up: switch-1 (192.168.1.10) on GigabitEthernet0/1
- router-1: interface_up (error) - %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
- router-1: interface_up (info) - %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_messy.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:20Z

## Executive Summary
- Total incidents reconstructed: 6
- Total events analyzed: 35
- Total causal links inferred: 31
- Affected devices: Access-6100-03, Access-6100-05, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0003 -> transceiver (device=Dist-6300-01, score=191.3)
- Incident INC-0004 -> dot1x_failure (device=Access-6100-03, score=54.3)
- Incident INC-0006 -> power_failure (device=Core-8325-01, score=218.2)
- Incident INC-0007 -> bgp_session_lost (device=Core-8325-01, score=36.6)
- Incident INC-0008 -> crc_errors (device=Access-6100-05, score=188.9)

## Incident Overview
- INC-0003: events=13, duration=179.892s, primary_issue=transceiver
- INC-0004: events=2, duration=5.559s, primary_issue=dot1x_failure
- INC-0005: events=2, duration=2.436s, primary_issue=ssh_bruteforce
- INC-0006: events=5, duration=12.214s, primary_issue=power_failure
- INC-0007: events=3, duration=5.873s, primary_issue=bgp_session_lost
- INC-0008: events=4, duration=15.0s, primary_issue=crc_errors

## Detailed Incident Chains
### INC-0003
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (warning)
- bgp_session_lost (warning)
- ospf (info)
- ospf (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- interface_up (info)
- ospf_neighbor_up (info)
- bgp_session_established (info)
- routes_relearned (info)

*Status: Resolved*
*Duration: 179.892s*

### INC-0004
**Failure Sequence:**
- dot1x_failure ×3 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 5.559s*

### INC-0005
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 2.436s*

### INC-0006
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)
- linecard_disabled (critical)

*Status: Active*
*Duration: 12.214s*

### INC-0007
**Failure Sequence:**
- bgp_session_lost (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)

*Status: Active*
*Duration: 5.873s*

### INC-0008
**Failure Sequence:**
- crc_errors ×2 (warning)
- interface_down (info)
- interface_down (info)
- lldp (info)

*Status: Active*
*Duration: 15.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0002
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0009
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)

### Workflow: WORKFLOW-0010
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info) x2

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- Core-8325-01: ntp (info) - NTP synchronized with server 192.168.10.1
- Core-8325-01: ntp (info) - NTP synchronized with server 192.168.10.1

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_prompt.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:23Z

## Executive Summary
- Total incidents reconstructed: 6
- Total events analyzed: 20
- Total causal links inferred: 4
- Affected devices: 192.168.1.104

## Probable Initiating Triggers
- Incident INC-0011 -> stp_topology_change (device=192.168.1.104, score=93.6)
- Incident INC-0013 -> power_failure (device=192.168.1.104, score=217.3)

## Incident Overview
- INC-0011: events=4, duration=188.0s, primary_issue=stp_topology_change
- INC-0013: events=2, duration=89.0s, primary_issue=power_failure
- INC-0004: events=1, duration=0.0s, primary_issue=dot1x_failure
- INC-0005: events=3, duration=145.0s, primary_issue=crc_errors
- INC-0009: events=1, duration=0.0s, primary_issue=admin_auth_failure
- INC-0010: events=1, duration=0.0s, primary_issue=ssh_bruteforce

## Detailed Incident Chains
### INC-0011
**Failure Sequence:**
- stp_topology_change (info)
- stp_topology_change (warning)
- ospf_neighbor_down (warning)

**Recovery Sequence:**
- bgp_session_established (info)

*Status: Recovering*
*Duration: 188.0s*

### INC-0013
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)

*Status: Active*
*Duration: 89.0s*

### INC-0004
**Failure Sequence:**
- dot1x_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0005
**Failure Sequence:**
- interface_down (info)
- crc_errors (warning)

**Recovery Sequence:**
- transceiver (info)

*Status: Active*
*Duration: 145.0s*

### INC-0009
**Failure Sequence:**
- admin_auth_failure (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0010
**Failure Sequence:**
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0007
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info)

### Workflow: WORKFLOW-0012
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.104: dot1x_failure (error) - 802.1x: Authentication failed for client 00:11:22:33:44:55 on port 1/1/5
- 192.168.1.104: interface_down (info) - Port 1/1/2 is now off-line
- 192.168.1.104: crc_errors (warning) - Port 1/1/12: Excessive CRC errors detected
- 192.168.1.104: transceiver (info) - Transceiver inserted in port 1/1/48
- 192.168.1.104: admin_auth_failure (warning) - Authentication failure for user admin from 192.168.1.99
- 192.168.1.104: ssh_bruteforce (critical) - SSH login failed from IP 203.0.113.5: Maximum attempts exceeded

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.104: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.104: interface_up (info) - Port 1/1/1 is now on-line
- 192.168.1.104: vlan (info) - Vlan 10 is created
- 192.168.1.104: lldp (info) - LLDP neighbor 00:25:B3:11:22:33 discovered on port 1/1/10
- 192.168.1.104: dot1x_logout (info) - 802.1x: Client 00:11:22:33:44:55 logged out from port 1/1/5
- 192.168.1.104: ntp (info) - NTP synchronized to time server 132.163.97.5

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_router1.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:25Z

## Executive Summary
- Total incidents reconstructed: 3
- Total events analyzed: 13
- Total causal links inferred: 1
- Affected devices: router-1

## Probable Initiating Triggers
- Incident INC-0004 -> interface_down (device=router-1, score=194.3)

## Incident Overview
- INC-0004: events=2, duration=2.0s, primary_issue=interface_down
- INC-0007: events=1, duration=0.0s, primary_issue=admin_auth_failure
- INC-0011: events=1, duration=0.0s, primary_issue=standalone_alert

## Detailed Incident Chains
### INC-0004
**Failure Sequence:**
- interface_down (error)
- interface_down (info)

*Status: Active*
*Duration: 2.0s*

### INC-0007
**Failure Sequence:**
- admin_auth_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0011
**Failure Sequence:**
- raw (critical)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0002
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0003
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - bgp (info)

### Workflow: WORKFLOW-0005
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - ospf_neighbor_down (info)

### Workflow: WORKFLOW-0006
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - ssh_bruteforce (info)

### Workflow: WORKFLOW-0010
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- router-1: admin_auth_failure (error) - %SNMP-3-AUTHFAIL: Authentication failure for SNMP req from host 10.0.0.250
- router-1: raw (critical) - %ENVIRONMENT-1-ALERT: Temp: Inlet 1 Temperature reading 41C, threshold 65C - normal

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- router-1: lldp (info) - %LLDP-5-NEIGHBOR: LLDP neighbor up: core-switch (192.168.1.10) on GigabitEthernet0/1
- router-1: interface_up (error) - %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
- router-1: interface_up (info) - %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/2, changed state to up
- router-1: ospf_neighbor_up (info) - %OSPF-5-ADJCHG: Process 1, Nbr 192.168.4.2 on Vlan30 from DOWN to FULL, Neighbor Up

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
============================================================
=== test_tunnel.log ===
============================================================

# Network Incident Investigation Report

Generated: 2026-06-25T18:26:29Z

## Executive Summary
- Total incidents reconstructed: 0
- Total events analyzed: 41
- Total causal links inferred: 0
- Affected devices: N/A

## Probable Initiating Triggers
- No high-confidence root trigger was detected

## Incident Overview
- No actionable incidents detected.

## Detailed Incident Chains
## Operational Workflows Detected

### Workflow: WORKFLOW-0001
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - vxlan_interface (info)
  - vni_create (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - tunnel_nexthop_add (info)
  - tunnel_operational (info)
  - vtep_operational (info) x8

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.