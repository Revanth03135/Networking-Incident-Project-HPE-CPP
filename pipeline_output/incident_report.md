# Network Incident Investigation Report

Generated: 2026-06-24T15:47:30Z

## Executive Summary
- Total incidents reconstructed: 6
- Total events analyzed: 45
- Total causal links inferred: 52
- Affected devices: Access-6100-02, Access-6100-03, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0001-1 -> bgp (device=Core-8325-01, score=136.3)
- Incident INC-0003 -> transceiver (device=Dist-6300-01, score=192.2)
- Incident INC-0004 -> ssh_source_blocked (device=Core-8325-01, score=52.0)
- Incident INC-0005 -> dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0006 -> power (device=Core-8325-01, score=218.2)
- Incident INC-0007 -> crc_errors (device=Access-6100-03, score=188.9)

## Incident Overview
- INC-0001-1: events=3, duration=285.0s, primary_issue=bgp
- INC-0003: events=16, duration=190.0s, primary_issue=transceiver
- INC-0004: events=2, duration=4.0s, primary_issue=ssh_source_blocked
- INC-0005: events=2, duration=6.0s, primary_issue=dot1x_failure
- INC-0006: events=5, duration=12.0s, primary_issue=power
- INC-0007: events=4, duration=10.0s, primary_issue=crc_errors

## Detailed Incident Chains
### INC-0001-1
**Failure Sequence:**
- config_change (info)
- bgp (warning)

**Recovery Sequence:**
- ntp (info)

*Status: Resolved*
*Duration: 285.0s*

### INC-0003
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (info)
- ospf_neighbor_down (warning)
- ospf (info)
- ospf (info)
- bgp (warning)
- bgp (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- interface_up (info)
- ospf (info)
- ospf (info)
- bgp (info)
- bgp (info)

*Status: Resolved*
*Duration: 190.0s*

### INC-0004
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 4.0s*

### INC-0005
**Failure Sequence:**
- dot1x_failure (error)
- port_blocked (warning)

*Status: Active*
*Duration: 6.0s*

### INC-0006
**Failure Sequence:**
- power (critical)
- fan (warning)
- thermal (warning)
- thermal (warning)
- thermal (critical)

*Status: Active*
*Duration: 12.0s*

### INC-0007
**Failure Sequence:**
- crc_errors (warning)
- interface_down (info)
- interface_down (info)
- lldp (info)

*Status: Active*
*Duration: 10.0s*

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- Core-8325-01: lldp (info) - LLDP neighbor discovered on port 1/1/10
- Core-8325-01: snmp (info) - Connection with 192.168.1.50 closed
- Core-8325-01: raw (info) - SSH access granted for user admin from 192.168.1.50
- Core-8325-01: ntp (info) - Time synchronized with server 192.168.1.1
- Core-8325-01: snmp (info) - SNMP session established with 192.168.1.50
- Core-8325-01: raw (info) - Running configuration modified by user admin
- Core-8325-01: ntp (info) - Time synchronized with server 192.168.1.1
- Core-8325-01: raw (info) - Startup configuration updated
- Core-8325-01: ntp (info) - Time synchronized with server 192.168.1.1
- Access-6100-01: mac_auth (info) - MAC Authentication successful for client 00:11:22:33:44:55
- Access-6100-01: mac_auth (info) - MAC Authentication successful for client 00:22:33:44:55:66
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