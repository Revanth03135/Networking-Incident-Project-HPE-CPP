# Network Incident Investigation Report

Generated: 2026-05-19T16:44:53Z

## Executive Summary
- Total incidents reconstructed: 1
- Total events analyzed: 3
- Total causal links inferred: 1
- Affected devices: CORE-RTR-W1, DNS-EAST-02, MONITOR-NODE-01

## Probable Initiating Triggers
- 1

## Incident Overview
- INC-0001: events=3, duration=2.0s, primary_issue=bgp

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.