# Network Incident Investigation Report

Generated: 2026-06-24T18:17:02Z

## Executive Summary
- Total incidents reconstructed: 4
- Total events analyzed: 19
- Total causal links inferred: 16
- Affected devices: Access-6100-02, Core-8325-01, Dist-6300-01

## Probable Initiating Triggers
- Incident INC-0002 -> transceiver (device=Dist-6300-01, score=197.8)
- Incident INC-0004 -> dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0005-1 -> power_failure (device=Core-8325-01, score=217.6)

## Incident Overview
- INC-0002: events=7, duration=241.0s, primary_issue=transceiver
- INC-0003: events=4, duration=15.0s, primary_issue=ssh_bruteforce
- INC-0004: events=2, duration=8.0s, primary_issue=dot1x_failure
- INC-0005-1: events=3, duration=25.0s, primary_issue=power_failure

## Detailed Incident Chains
### INC-0002
**Failure Sequence:**
- transceiver (warning)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (warning)
- ospf_neighbor_up (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)

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
- dot1x_failure (error)
- raw (warning)

*Status: Active*
*Duration: 8.0s*

### INC-0005-1
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (critical)

*Status: Active*
*Duration: 25.0s*

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- Core-8325-01: raw (warning) - Internal temperature exceeded warning threshold

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