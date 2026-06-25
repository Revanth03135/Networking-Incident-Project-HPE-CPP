# Network Incident Investigation Report

Generated: 2026-06-25T18:21:49Z

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