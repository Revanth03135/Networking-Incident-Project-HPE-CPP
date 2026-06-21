# Network Incident Investigation Report

Generated: 2026-06-20T20:21:15Z

## Executive Summary
- Total incidents reconstructed: 5
- Total events analyzed: 10
- Total causal links inferred: 5
- Affected devices: router-2

## Probable Initiating Triggers
- Incident INC-0001 -> lldp (device=router-2, score=-54.0)
- Incident INC-0002 -> ospf (device=router-2, score=151.9)
- Incident INC-0003 -> power (device=router-2, score=178.0)
- Incident INC-0004 -> temperature (device=router-2, score=36.0)
- Incident INC-0005 -> authentication (device=router-2, score=28.0)

## Incident Overview
- INC-0001: events=1, duration=0.0s, primary_issue=unknown
- INC-0002: events=6, duration=2240.0s, primary_issue=unknown
- INC-0003: events=1, duration=0.0s, primary_issue=unknown
- INC-0004: events=1, duration=0.0s, primary_issue=unknown
- INC-0005: events=1, duration=0.0s, primary_issue=unknown

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.