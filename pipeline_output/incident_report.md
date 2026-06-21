# Network Incident Investigation Report

Generated: 2026-06-21T19:04:28Z

## Executive Summary
- Total incidents reconstructed: 12
- Total events analyzed: 20
- Total causal links inferred: 5
- Affected devices: 192.168.1.104

## Probable Initiating Triggers
- Incident INC-0004-1 -> dot1x_failure (device=192.168.1.104, score=54.3)
- Incident INC-0010-1 -> stp_topology_change (device=192.168.1.104, score=101.3)
- Incident INC-0011 -> power (device=192.168.1.104, score=217.3)

## Incident Overview
- INC-0004-1: events=2, duration=971.0s, primary_issue=dot1x_failure
- INC-0010-1: events=3, duration=188.0s, primary_issue=stp_topology_change
- INC-0011: events=2, duration=89.0s, primary_issue=power

## Detailed Incident Chains
### INC-0004-1
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_logout (info)

*Duration: 971.0s*

### INC-0010-1
**Failure Sequence:**
- stp_topology_change (info)
- stp_topology_change (warning)
- ospf_neighbor_down (warning)

*Duration: 188.0s*

### INC-0011
**Failure Sequence:**
- power (critical)
- fan (warning)

*Duration: 89.0s*

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.104: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.104: interface_up (info) - Port 1/1/1 is now on-line
- 192.168.1.104: vlan (info) - Vlan 10 is created
- 192.168.1.104: mac_auth_success (info) - MAC-Auth: Client 00:AA:BB:CC:DD:EE successfully authenticated on port 1/1/4
- 192.168.1.104: admin_auth_failure (warning) - Authentication failure for user admin from 192.168.1.99
- 192.168.1.104: interface_down (info) - Port 1/1/2 is now off-line
- 192.168.1.104: crc_errors (warning) - Port 1/1/12: Excessive CRC errors detected
- 192.168.1.104: transceiver (info) - Transceiver inserted in port 1/1/48
- 192.168.1.104: lldp (info) - LLDP neighbor 00:25:B3:11:22:33 discovered on port 1/1/10
- 192.168.1.104: ssh_bruteforce (critical) - SSH login failed from IP 203.0.113.5: Maximum attempts exceeded
- 192.168.1.104: config_change (info) - Configuration changed by user 'admin' via ssh from 192.168.1.50
- 192.168.1.104: ntp (info) - NTP synchronized to time server 132.163.97.5

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.