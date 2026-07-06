# Network Incident Investigation Report

Generated: 2026-07-02T16:12:01Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 8
- Total causal links inferred: 3
- Affected devices: Access-SW1

## Probable Initiating Triggers
- Incident INC-0006 -> Root Cause: crc_errors (device=Access-SW1, score=188.6)

## Incident Overview
- INC-0006: events=3, duration=6.021s, primary_issue=crc_errors

## Detailed Incident Chains
### INC-0006
**Failure Sequence:**
- crc_errors (warning)
- interface (warning)
- lacp (info)

*Status: Active*
*Duration: 6.021s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0002
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info)

### Workflow: WORKFLOW-0003
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - system (info)

### Workflow: WORKFLOW-0004
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - system (info)

### Workflow: WORKFLOW-0005
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - system (info)

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.104: lldp (info) - LLDP neighbor 00:25:B3:11:22:33 discovered on port 1/1/10

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.